"""DNS Authenticator for BaiduCdn."""
import json
import logging
import time
import base64
from hashlib import sha1
import hmac

import requests
import zope.interface

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common


logger = logging.getLogger(__name__)

API_ENDPOINT = "https://api.su.baidu.com/%s"

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for BaiduCdn

    This Authenticator uses the BaiduCdn Remote REST API to fulfill a dns-01 challenge.
    """

    description = "Obtain certificates using a DNS TXT record (if you are using BaiduCdn for DNS)."
    ttl = 300

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=30
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
                'access-key': 'AccessKey for Baidu DNS, obtained from BaiduCdn',
                'secret-key': 'SecretKey for Baidu DNS, obtained from AliyunCdn'
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_baidu_client().add_txt_record(
            domain, validation_name, validation
        )

    def _cleanup(self, domain, validation_name, validation):
        self._get_baidu_client().del_txt_record(
            domain, validation_name, validation
        )

    def _get_baidu_client(self):
        return BaiduCdnClient(
                self.credentials.conf('access-key'),
                self.credentials.conf('secret-key'),
                self.ttl)


class BaiduCdnClient():
    """
    Encapsulates all communication with the BaiduCdn Remote REST API.
    """

    _access_key = ''
    _secret_key = ''
    _ttl = 300

    _sign_method = "HMAC-SHA1"

    def __init__(self, access_key, secret_key, ttl = 300):
        logger.debug("getting access-key and secret-key")
        self._access_key = access_key
        self._secret_key = secret_key
        self._ttl = ttl
            
    def get_signature(self, sec_key, text):
        hmac_code = hmac.new(sec_key.encode(), text.encode(), sha1).digest()
        return base64.b64encode(hmac_code).decode()
    
    def get_inited_common_params(self, path):
        param_map = {}

        auth_timestamp = str(int(time.time()))
        param_map['X-Auth-Access-Key'] = self._access_key
        param_map['X-Auth-Nonce'] = auth_timestamp
        param_map['X-Auth-Path-Info'] = path
        param_map['X-Auth-Signature-Method'] = self._sign_method
        param_map['X-Auth-Timestamp'] = auth_timestamp
        # param_map['ttl'] = str(self._ttl)

        return param_map

    def smart_str(self, target_string):
        if isinstance(target_string, str):
            return target_string
        else:
            return json.dumps(target_string)
    
    def get_parsed_all_params(self, params):
        keys = sorted(params.keys())
        return "&".join(["%s=%s" % (str(k), self.smart_str(params[k])) for k in keys])

    def get_request_header(self, path, query_params, body_params):
        common_params = self.get_inited_common_params(path)
        all_params = {}
        headers = {}

        headers.update(common_params)

        all_params.update(common_params)
        all_params.update(query_params)
        all_params.update(body_params)

        all_params_str = self.get_parsed_all_params(all_params)

        print(all_params_str)

        sign = self.get_signature(self._secret_key, all_params_str)

        headers["X-Auth-Sign"] = sign

        return headers

    def send_http_request(self, method='GET', url='', params=None, payload=None, headers=None):
        if params is None:
            params = {}
        if payload is None:
            payload = {}
        if headers is None:
            headers = {}

        # print(params, payload, headers)
            
        resp = requests.request(method, url, params=params, data=json.dumps(payload), headers=headers)
        
        return resp

    def add_txt_record(self, domain, record_name, value):
        path = "v31/yjs/zones/dns_records"
        params = {}

        payload = {}
        payload['domain'] = domain
        payload['subdomain'] = record_name
        payload['type'] = 'TXT'
        payload['content'] = value
        payload['ttl'] = self._ttl

        headers = self.get_request_header(path, params, payload)

        url = API_ENDPOINT % path
        
        res = self.send_http_request("POST", url, params=params, payload=payload, headers=headers)
        print(res.json())

    def del_txt_record(self, domain, record_name, value):
        path = "v31/yjs/zones"
        params = {}
        
        payload = {}
        payload['domain'] = domain
        payload['subdomain'] = record_name
        payload['content'] = value
        payload['isp_uuid'] = 'default'

        headers = self.get_request_header(path, params, payload)

        url = API_ENDPOINT % path

        res = self.send_http_request("DELETE", url, params=params, payload=payload, headers=headers)
        print(res.json())

    def view_txt_record(self, domain, record_name, value):
        path = "v31/yjs/zones"
        params = {}
        
        payload = {}
        params['name'] = 'asteriscum.cn'
        params["type"] = "ns"

        headers = self.get_request_header(path, params, payload)

        url = API_ENDPOINT % path

        response = self.send_http_request("POST", url, params=params, payload=payload, headers=headers)
        print(response.json())