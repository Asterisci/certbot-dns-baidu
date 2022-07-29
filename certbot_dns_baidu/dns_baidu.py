"""DNS Authenticator for BaiduCdn."""
import hmac
import json
import logging
import time
import urllib.parse

import requests
import zope.interface

from http import HTTPStatus
from hashlib import sha256

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

logger = logging.getLogger(__name__)

API_ENDPOINT = "https://bcd.baidubce.com"

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for BaiduCdn

    This Authenticator uses the BaiduCdn Remote REST API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using BaiduCdn for DNS)."
    ttl = 300
    _baidudns_client = None

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=120
        )
        add("credentials", help="BaiduCdn credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            + "the BaiduCdn Remote REST API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "BaiduCdn credentials INI file",
            {
                'access_key': 'AccessKey for Baidu DNS, obtained from BaiduCdn',
                'secret_key': 'SecretKey for Baidu DNS, obtained from BaiduCdn'
            }
        )

    def _perform(self, domain, validation_name, validation):
        logger.debug("getting domain:{}, validation_name: {} and validation: {}".format(domain, validation_name, validation))
        self._get_baidu_client().add_txt_record(
            domain, validation_name, validation
        )

    def _cleanup(self, domain, validation_name, validation):
        self._get_baidu_client().del_txt_record(
            domain, validation_name, validation
        )

    def _get_baidu_client(self):
        logger.debug("getting access-key:{} and secret-key: {}".format(self.credentials.conf('access_key'), self.credentials.conf('secret_key')))
        if not self._baidudns_client:
            self._baidudns_client = _BaiduCdnClient(
                self.credentials.conf('access_key'),
                self.credentials.conf('secret_key'),
                self.ttl
            )
        return self._baidudns_client


class _BaiduCdnClient(dns_common_lexicon.LexiconClient):
    """
    Encapsulates all communication with the BaiduCdn Remote REST API.
    """

    _access_key = ''
    _secret_key = ''
    _ttl = 300

    def __init__(self, access_key, secret_key, ttl = 300):
        logger.debug("getting access-key:{} and secret-key: {}".format(access_key, secret_key))
        self._access_key = access_key
        self._secret_key = secret_key
        self._ttl = ttl

    def _identify_base_domain(self, domain):
        candidates = dns_common.base_domain_name_guesses(domain)
        uri = "/v1/domain/detail"
        method="GET"
        for candidate in candidates:
            queries = {
                "domain": candidate
            }
            resp = self.send_api_request(method=method, uri=uri, queries=queries)
            if resp.status_code == HTTPStatus.OK:
                return candidate
        raise errors.PluginError(f"Unable to identify base domain for {domain}, tried {candidates}")

    def _find_domain_record_ids(self, domain, rr, value):
        uri = "/v1/domain/resolve/list"
        method = "POST"
        payloads = {
            "domain": domain
        }
        resp = self.send_api_request(method=method, uri=uri, payloads=payloads)
        if resp.status_code != HTTPStatus.OK:
            raise errors.PluginError(f"Unable to get domain resolve lists for {domain}")
        resolves = resp.json()["result"]
        for resolve in resolves:
            if rr == resolve['domain'] and value == resolve['rdata']:
                return resolve['recordId']
        raise errors.PluginError(f"Unable to get record id for domain {domain}")

    def get_request_header(self, method, uri, queries):
        x_bce_date = time.gmtime()
        x_bce_date = time.strftime('%Y-%m-%dT%H:%M:%SZ', x_bce_date)
        headers = {
            "Host": "bcd.baidubce.com",
            "content-type": "application/json;charset=utf-8",
            "x-bce-date": x_bce_date
        }

        authStringPrefix = f"bce-auth-v1/{self._access_key}/{x_bce_date}/1800"
        
        CanonicalURI = urllib.parse.quote(uri)

        CanonicalQueryGroups = []
        for key, value in queries.items():
            query_processed = f"{urllib.parse.quote(key, safe='')}={urllib.parse.quote(value, safe='')}"
            CanonicalQueryGroups.append(query_processed)
        CanonicalQueryGroups.sort()
        CanonicalQueryString = "&".join(CanonicalQueryGroups)

        CanonicalHeaderGroups = []
        for key, value in headers.items():
            headerProcessed = f"{urllib.parse.quote(key.lower(), safe='')}:{urllib.parse.quote(value, safe='')}"
            CanonicalHeaderGroups.append(headerProcessed)
        CanonicalHeaderGroups.sort()
        CanonicalHeaderString = "\n".join(CanonicalHeaderGroups)
        
        CanonicalRequest = f"{method}\n{CanonicalURI}\n{CanonicalQueryString}\n{CanonicalHeaderString}"
        
        signingKey = hmac.new(self._secret_key.encode('utf-8'), 
                     authStringPrefix.encode('utf-8'), sha256)
        signature = hmac.new(signingKey.hexdigest().encode('utf-8'),
                     CanonicalRequest.encode('utf-8'), sha256)

        signedHeaders = "content-type;host;x-bce-date"
        headers["Authorization"] = f"{authStringPrefix}/{signedHeaders}/{signature.hexdigest()}"

        return headers

    def send_api_request(self, method, uri, queries={}, payloads={}):
        url = f"{API_ENDPOINT}{uri}"
        headers = self.get_request_header(method=method, uri=uri, queries=queries)
        resp = requests.request(method, url, params=queries, data=json.dumps(payloads), headers=headers)
        return resp

    def add_txt_record(self, domain, record_name, value):
        uri = "/v1/domain/resolve/add"
        method = "POST"

        domain = self._identify_base_domain(domain=domain)
        rr = record_name[:record_name.rindex(f".{domain}")]

        queries = {}
        payloads = {
            "domain": rr,
            "rdType": "TXT",
            "rdata": value,
            "zoneName": domain,
            "ttl": self._ttl
        }

        self.send_api_request(method=method, uri=uri, queries=queries, payloads=payloads)

    def del_txt_record(self, domain, record_name, value):
        uri = "/v1/domain/resolve/delete"
        method = "POST"
        
        domain = self._identify_base_domain(domain=domain)
        rr = record_name[:record_name.rindex(f".{domain}")]
        record_id = self._find_domain_record_ids(domain=domain, rr=rr, value=value)

        queries = {}
        payloads = {
            "zoneName": domain,
            "recordId": record_id
        }
        self.send_api_request(method=method, uri=uri, queries=queries, payloads=payloads)