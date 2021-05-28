"""Tests for dns_baidu and certbot_dns_baidu.dns_baidu."""

import os
import unittest

from dns_baidu import _BaiduCdnClient

import mock
from requests.exceptions import HTTPError, RequestException

from certbot.plugins import dns_test_common
from certbot.plugins import dns_test_common_lexicon
from certbot.tests import util as test_util


ACCESS_KEY = '123456'
SECRET_KEY = '123456'
DOMAIN_NAME = 'a.example.c'

DOMAIN_NOT_FOUND = Exception('No domain found')
GENERIC_ERROR = RequestException
LOGIN_ERROR = HTTPError('400 Client Error: ...')

class _BaiduCdnClientTest(unittest.TestCase):

    _client = None

    def setUp(self):
        super(_BaiduCdnClientTest, self).setUp()
        self._client = _BaiduCdnClient(ACCESS_KEY, SECRET_KEY)

    def test_add_txt_record(self):
        self._client.add_txt_record(DOMAIN_NAME, 'test.' + DOMAIN_NAME, 'test')

    def test_del_txt_record(self):
        self._client.del_txt_record(DOMAIN_NAME, 'test.' + DOMAIN_NAME, 'test')

class AuthenticatorTest(test_util.TempDirTestCase,
                        dns_test_common_lexicon.BaseLexiconAuthenticatorTest):

    def setUp(self):
        super(AuthenticatorTest, self).setUp()

        from certbot_dns_baidu.dns_baidu import Authenticator

        path = os.path.join(self.tempdir, 'file.ini')
        dns_test_common.write({
            "baidu_access_key": ACCESS_KEY,
            "baidu_secret_key": SECRET_KEY
        }, path)

        self.config = mock.MagicMock(baidu_credentials=path,
                                     baidu_propagation_seconds=0)  # don't wait during tests

        self.auth = Authenticator(self.config, "baidu")

        self.mock_client = mock.MagicMock()
        # _get_baidu_client | pylint: disable=protected-access
        self.auth._get_baidu_client = mock.MagicMock(return_value=self.mock_client)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover

