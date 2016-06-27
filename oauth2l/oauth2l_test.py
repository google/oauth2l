#
# Copyright 2015 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for oauth2l."""

import json
import os
import sys
import unittest

import httplib2
import mock
import oauth2client.client
import oauth2client.contrib.multistore_file
import oauth2client.service_account
import oauth2client.tools
import six
from six.moves import http_client

import oauth2l


def _GetCommandOutput(command_name, command_argv):
    orig_stdout = sys.stdout
    orig_stderr = sys.stderr
    new_stdout = six.StringIO()
    new_stderr = six.StringIO()
    try:
        sys.stdout = new_stdout
        sys.stderr = new_stderr
        oauth2l.main(['oauth2l', command_name] + command_argv)
    finally:
        sys.stdout = orig_stdout
        sys.stderr = orig_stderr
    new_stdout.seek(0)
    return new_stdout.getvalue().rstrip()


class InvalidCommandTest(unittest.TestCase):

    def testOutput(self):
        self.assertRaises(SystemExit,
                          _GetCommandOutput, 'foo', [])


class Oauth2lFormattingTest(unittest.TestCase):

    def setUp(self):
        # Set up an access token to use
        self.access_token = 'ya29.abdefghijklmnopqrstuvwxyz'
        self.user_agent = 'oauth2l/1.0'
        self.credentials = oauth2client.client.AccessTokenCredentials(
            self.access_token, self.user_agent)
        patcher = mock.patch(
            'oauth2l._FetchCredentials', return_value=self.credentials,
            autospec=True)
        self.mock_fetch = patcher.start()
        self.addCleanup(patcher.stop)

    def _Args(self, credentials_format):
        return ['--credentials_format=' + credentials_format, 'userinfo.email']

    def testFormatBare(self):
        output = _GetCommandOutput('fetch', self._Args('bare'))
        self.assertEqual(self.access_token, output)
        self.assertEqual(1, self.mock_fetch.call_count)

    def testFormatHeader(self):
        output = _GetCommandOutput('fetch', self._Args('header'))
        header = 'Authorization: Bearer %s' % self.access_token
        self.assertEqual(header, output)
        self.assertEqual(1, self.mock_fetch.call_count)

    def testHeaderCommand(self):
        output = _GetCommandOutput('header', ['userinfo.email'])
        header = 'Authorization: Bearer %s' % self.access_token
        self.assertEqual(header, output)
        self.assertEqual(1, self.mock_fetch.call_count)

    def testFormatJson(self):
        output = _GetCommandOutput('fetch', self._Args('json'))
        output_lines = [l.strip() for l in output.splitlines()]
        expected_lines = [
            '"_class": "AccessTokenCredentials",',
            '"access_token": "%s",' % self.access_token,
        ]
        for line in expected_lines:
            self.assertIn(line, output_lines)
        self.assertEqual(1, self.mock_fetch.call_count)

    def testFormatJsonCompact(self):
        output = _GetCommandOutput('fetch', self._Args('json_compact'))
        expected_clauses = [
            '"_class":"AccessTokenCredentials",',
            '"access_token":"%s",' % self.access_token,
        ]
        for clause in expected_clauses:
            self.assertIn(clause, output)
        self.assertEqual(1, len(output.splitlines()))
        self.assertEqual(1, self.mock_fetch.call_count)

    def testFormatPretty(self):
        output = _GetCommandOutput('fetch', self._Args('pretty'))
        expecteds = ['oauth2client.client.AccessTokenCredentials',
                     self.access_token]
        for expected in expecteds:
            self.assertIn(expected, output)
        self.assertEqual(1, self.mock_fetch.call_count)

    def testFakeFormat(self):
        with self.assertRaises(ValueError):
            oauth2l._Format('xml', self.credentials)


class TestFetch(unittest.TestCase):

    def setUp(self):
        # Set up an access token to use
        self.access_token = 'ya29.abdefghijklmnopqrstuvwxyz'
        self.user_agent = 'oauth2l/1.0'
        self.credentials = oauth2client.client.AccessTokenCredentials(
            self.access_token, self.user_agent)

        patcher_3lo = mock.patch(
            'oauth2l._GetCredentialsVia3LO', return_value=self.credentials,
            autospec=True)
        self.mock_3lo = patcher_3lo.start()
        self.addCleanup(patcher_3lo.stop)

        patcher_adc = mock.patch(
            'oauth2l._GetApplicationDefaultCredentials', return_value=None,
            autospec=True)
        self.mock_adc = patcher_adc.start()
        self.addCleanup(patcher_adc.stop)

    def testNoScopes(self):
        output = _GetCommandOutput('fetch', [])
        self.assertEqual(
            'Error encountered in fetch operation: No scopes provided',
            output)

    @mock.patch.object(oauth2l, '_GetTokenInfo', autospec=True)
    def testScopes(self, mock_get_info):
        expected_scopes = [
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/cloud-platform',
        ]
        mock_get_info.return_value = {
            'email': 'user@gmail.com',
            'expires_in': 123,
            'scope': ' '.join(expected_scopes),
        }
        output = _GetCommandOutput(
            'fetch', ['userinfo.email', 'cloud-platform'])
        self.assertIn(self.access_token, output)
        self.assertEqual(1, self.mock_adc.call_count)
        self.assertEqual(1, self.mock_3lo.call_count)
        self.assertEqual(1, mock_get_info.call_count)
        self.assertEqual((self.access_token,), mock_get_info.call_args[0])

    def testNoCredentials(self):
        self.mock_3lo.return_value = None
        output = _GetCommandOutput('fetch', ['userinfo.email'])
        self.assertIn('Failed to fetch credentials', output)
        self.assertEqual(1, self.mock_adc.call_count)
        self.assertEqual(1, self.mock_3lo.call_count)

    @mock.patch.object(oauth2l, '_TestToken', return_value=False,
                       autospec=True)
    def testCredentialsRefreshed(self, mock_test):
        with mock.patch.object(self.credentials, 'refresh',
                               return_value=None,
                               autospec=True) as mock_refresh:
            output = _GetCommandOutput('fetch', ['userinfo.email'])
            self.assertIn(self.access_token, output)
            self.assertEqual(1, self.mock_adc.call_count)
            self.assertEqual(1, self.mock_3lo.call_count)
            self.assertEqual(1, mock_test.call_count)
            self.assertEqual(1, mock_refresh.call_count)

    @mock.patch.object(oauth2l, '_TestToken', return_value=True,
                       autospec=True)
    def testDefaultClientInfo(self, mock_test):
        output = _GetCommandOutput('fetch', ['userinfo.email'])
        self.assertIn(self.access_token, output)
        self.assertEqual(1, self.mock_adc.call_count)
        self.assertEqual(1, self.mock_3lo.call_count)
        self.assertEqual(1, mock_test.call_count)
        args, _ = self.mock_3lo.call_args
        client_info = args[0]
        self.assertEqual(
            ('1055925038659-sb6bdak55edef9a0joshf24g7i2kiatf'
             '.apps.googleusercontent.com'),
            client_info['client_id'])
        self.assertEqual(1, mock_test.call_count)

    def testMissingClientSecrets(self):
        with self.assertRaises(ValueError):
            oauth2l.GetClientInfoFromFile('/non/existent/file')

    def testWrongClientSecretsFormat(self):
        client_secrets = os.path.join(
            os.path.dirname(__file__),
            'testdata/noninstalled_client_secrets.json')
        with self.assertRaises(ValueError):
            oauth2l.GetClientInfoFromFile(client_secrets)

    @mock.patch.object(oauth2l, '_TestToken', return_value=True, autospec=True)
    def testCustomClientInfo(self, mock_test):
        client_secrets_path = os.path.join(
            os.path.dirname(__file__), 'testdata/fake_client_secrets.json')
        fetch_args = ['--json=' + client_secrets_path, 'userinfo.email']
        output = _GetCommandOutput('fetch', fetch_args)
        self.assertIn(self.access_token, output)
        self.assertEqual(1, self.mock_3lo.call_count)
        args, _ = self.mock_3lo.call_args
        client_info = args[0]
        self.assertEqual('144169.apps.googleusercontent.com',
                         client_info['client_id'])
        self.assertEqual('awesomesecret', client_info['client_secret'])
        self.assertEqual(1, mock_test.call_count)


class TestOtherCommands(unittest.TestCase):

    def setUp(self):
        # Set up an access token to use
        self.access_token = 'ya29.abdefghijklmnopqrstuvwxyz'
        self.user_agent = 'oauth2l/1.0'
        self.credentials = oauth2client.client.AccessTokenCredentials(
            self.access_token, self.user_agent)

    def testInvalidJsonFile(self):
        output = _GetCommandOutput('fetch', ['--json', __file__])
        self.assertIn('Invalid JSON file', output)

    def testInfo(self):
        info_json = '\n'.join((
            '{',
            '    "email": "foo@example.com",',
            '    "expires_in": 456,',
            '    "scope": "scope2 scope1"',
            '}',
        ))
        info = json.loads(info_json)
        with mock.patch.object(oauth2l, '_GetTokenInfo',
                               return_value=info,
                               autospec=True) as mock_get_tokeninfo:
            output = _GetCommandOutput('info', [self.access_token])
            self.assertEqual(1, mock_get_tokeninfo.call_count)
            self.assertEqual(self.access_token,
                             mock_get_tokeninfo.call_args[0][0])
            self.assertEqual(info_json, output)

    def testInfoNoEmail(self):
        info = {
            'expires_in': 456,
            'scope': 'scope2 scope1',
        }
        with mock.patch.object(oauth2l, '_GetTokenInfo',
                               return_value=info,
                               autospec=True) as mock_get_tokeninfo:
            output = _GetCommandOutput('info', [self.access_token])
            self.assertEqual(1, mock_get_tokeninfo.call_count)
            self.assertEqual(self.access_token,
                             mock_get_tokeninfo.call_args[0][0])
            self.assertIn('scope2 scope1', output)
            self.assertNotIn('email', output)

    def testInfoJsonCompact(self):
        info_json = ('{"email":"foo@example.com","expires_in":456,'
                     '"scope":"scope2 scope1"}')
        info = json.loads(info_json)
        with mock.patch.object(oauth2l, '_GetTokenInfo',
                               return_value=info,
                               autospec=True) as mock_get_tokeninfo:
            output = _GetCommandOutput(
                'info', ['-f', 'json_compact', self.access_token])
            self.assertEqual(1, mock_get_tokeninfo.call_count)
            self.assertEqual(self.access_token,
                             mock_get_tokeninfo.call_args[0][0])
            self.assertEqual(info_json, output)

    def testTest(self):
        scopes = [u'https://www.googleapis.com/auth/userinfo.email',
                  u'https://www.googleapis.com/auth/cloud-platform']
        content = json.dumps({'scope': ' '.join(scopes)})
        if isinstance(content, bytes):
            content = content.decode('utf8')
        with mock.patch.object(httplib2, 'Http', autospec=True) as mock_http:
            mock_http.return_value = mock_h = mock.MagicMock()
            mock_h.request.return_value = ({'status': '200'}, content)
            output = _GetCommandOutput('test', [self.access_token])
            self.assertEqual('', output)
            self.assertEqual(1, mock_h.request.call_count)
            self.assertEqual(1, mock_http.call_count)

    def testBadResponseCode(self):
        with mock.patch.object(httplib2, 'Http', autospec=True) as mock_http:
            mock_http.return_value = mock_h = mock.MagicMock()
            mock_h.request.return_value = ({'status': '400'}, 'Error')
            output = _GetCommandOutput('info', [self.access_token])
            self.assertEqual('', output)
            self.assertEqual(1, mock_http.call_count)
            self.assertEqual(1, mock_h.request.call_count)

    def testUnexpectedResponseCode(self):
        with mock.patch.object(httplib2, 'Http', autospec=True) as mock_http:
            mock_http.return_value = mock_h = mock.MagicMock()
            mock_h.request.return_value = ({'status': '500'}, 'Error')
            output = _GetCommandOutput('info', [self.access_token])
            self.assertIn('500', output)
            self.assertIn('Error making HTTP request to <', output)
            self.assertEqual(1, mock_http.call_count)
            self.assertEqual(1, mock_h.request.call_count)

    def testMissingStatus(self):
        with mock.patch.object(httplib2, 'Http', autospec=True) as mock_http:
            mock_http.return_value = mock_h = mock.MagicMock()
            mock_h.request.return_value = ({}, 'Error')
            output = _GetCommandOutput('info', [self.access_token])
            self.assertIn('No status in HTTP response', output)
            self.assertEqual(1, mock_http.call_count)
            self.assertEqual(1, mock_h.request.call_count)


class TestServiceAccounts(unittest.TestCase):
    def setUp(self):
        # Set up an access token to use
        self.access_token = 'ya29.abdefghijklmnopqrstuvwxyz'
        self.user_agent = 'oauth2l/1.0'
        self.credentials = oauth2client.client.AccessTokenCredentials(
            self.access_token, self.user_agent)

        patcher_service_account = mock.patch(
            'oauth2client.service_account.ServiceAccountCredentials',
            autospec=True)
        self.mock_sa = patcher_service_account.start()
        self.mock_sa.from_json_keyfile_name = self.from_keyfile = (
            mock.MagicMock())
        self.from_keyfile.return_value = self.credentials
        self.addCleanup(patcher_service_account.stop)

    @mock.patch.object(oauth2l, '_TestToken', return_value=True,
                       autospec=True)
    def testServiceAccounts(self, mock_test):
        service_account_path = os.path.join(
            os.path.dirname(__file__), 'testdata/fake_service_account.json')
        fetch_args = ['--json=' + service_account_path, 'userinfo.email']
        output = _GetCommandOutput('fetch', fetch_args)
        self.assertIn(self.access_token, output)
        self.assertEqual(1, self.from_keyfile.call_count)
        self.assertEqual(1, mock_test.call_count)


class TestADC(unittest.TestCase):
    def setUp(self):
        # Set up an access token to use
        self.access_token = 'ya29.abdefghijklmnopqrstuvwxyz'
        self.user_agent = 'oauth2l/1.0'
        self.credentials = oauth2client.client.AccessTokenCredentials(
            self.access_token, self.user_agent)
        self.credentials.create_scoped_required = lambda: False

    @mock.patch.object(oauth2client.client, 'GoogleCredentials', autospec=True)
    def testNoAdc(self, mock_gc):
        mock_gc.get_application_default = mock_get = mock.MagicMock()
        mock_get.side_effect = (
            oauth2client.client.ApplicationDefaultCredentialsError())
        self.assertIsNone(oauth2l._GetApplicationDefaultCredentials([]))

        mock_get.side_effect = None
        mock_get.return_value = None
        self.assertIsNone(oauth2l._GetApplicationDefaultCredentials([]))

    @mock.patch.object(oauth2client.client, 'GoogleCredentials', autospec=True)
    def testAdc(self, mock_gc):
        mock_gc.get_application_default = mock_get = mock.MagicMock()
        mock_get.return_value = self.credentials
        self.assertIsNotNone(oauth2l._GetApplicationDefaultCredentials([]))
        self.assertEqual(1, mock_get.call_count)

    @mock.patch.object(oauth2client.client, 'GoogleCredentials', autospec=True)
    def testAdcScopes(self, mock_gc):
        credentials = oauth2client.client.AccessTokenCredentials(
            self.access_token, self.user_agent)
        mock_gc.get_application_default = mock_get = mock.MagicMock()
        mock_get.return_value = credentials
        credentials.create_scoped_required = lambda: True
        credentials.create_scoped = lambda _: credentials
        self.assertIsNotNone(oauth2l._GetApplicationDefaultCredentials([]))
        self.assertEqual(1, mock_get.call_count)
        self.assertIsNone(
            oauth2l._GetApplicationDefaultCredentials(['turkey']))
        self.assertEqual(2, mock_get.call_count)


class Test3LO(unittest.TestCase):

    def setUp(self):
        # Set up an access token to use
        self.access_token = 'ya29.abdefghijklmnopqrstuvwxyz'
        self.user_agent = 'oauth2l/1.0'
        self.credentials = oauth2client.client.AccessTokenCredentials(
            self.access_token, self.user_agent)

        patcher_adc = mock.patch(
            'oauth2l._GetApplicationDefaultCredentials', return_value=None,
            autospec=True)
        self.mock_adc = patcher_adc.start()
        self.addCleanup(patcher_adc.stop)

        patcher_test = mock.patch(
            'oauth2l._TestToken', return_value=True, autospec=True)
        self.mock_test = patcher_test.start()
        self.addCleanup(patcher_test.stop)

    @mock.patch('oauth2client.contrib.multistore_file.get_credential_storage',
                autospec=True)
    @mock.patch('oauth2client.tools.run_flow', autospec=True)
    def test3LO(self, mock_run_flow, mock_get_storage):
        mock_get_storage.return_value = mock_store = mock.MagicMock()
        mock_store.get.return_value = None
        mock_run_flow.return_value = self.credentials
        output = _GetCommandOutput('fetch', ['userinfo.email'])
        self.assertIn(self.access_token, output)
        self.assertEqual(1, mock_store.get.call_count)
        self.assertEqual(1, self.mock_test.call_count)

    @mock.patch('oauth2client.contrib.multistore_file.get_credential_storage',
                autospec=True)
    @mock.patch('oauth2client.tools.run_flow', autospec=True)
    def testHttpFailure(self, mock_run_flow, mock_get_storage):
        mock_get_storage.return_value = mock_store = mock.MagicMock()
        mock_store.get.return_value = None
        mock_run_flow.side_effect = httplib2.HttpLib2Error
        output = _GetCommandOutput('fetch', ['userinfo.email'])
        self.assertIn('Communication error creating credentials', output)
        self.assertEqual(1, mock_store.get.call_count)
        self.assertEqual(0, self.mock_test.call_count)

    @mock.patch('oauth2client.contrib.multistore_file.get_credential_storage',
                autospec=True)
    def testCached(self, mock_get_storage):
        mock_get_storage.return_value = mock_store = mock.MagicMock()
        mock_store.get.return_value = self.credentials
        output = _GetCommandOutput('fetch', ['userinfo.email'])
        self.assertIn(self.access_token, output)
        self.assertEqual(1, mock_store.get.call_count)
        self.assertEqual(1, self.mock_test.call_count)

    @mock.patch('oauth2client.client.OAuth2WebServerFlow',
                side_effect=SystemExit(), autospec=True)
    @mock.patch('oauth2client.contrib.multistore_file.get_credential_storage',
                autospec=True)
    def testCachedInvalid(self, mock_get_storage, mock_flow):
        mock_get_storage.return_value = mock_store = mock.MagicMock()
        mock_store.get.return_value = self.credentials
        credentials = oauth2client.client.AccessTokenCredentials(
            self.access_token, self.user_agent)
        mock_store.get.return_value = credentials
        credentials.invalid = True
        output = _GetCommandOutput('fetch', ['fake.scope'])
        self.assertIn('Failed to fetch credentials', output)
