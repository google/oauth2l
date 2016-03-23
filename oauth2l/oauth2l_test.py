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

import mock
import oauth2client.client
import six
from six.moves import http_client

import apitools.base.py as apitools_base
import oauth2l

_OAUTH2L_MAIN_RUN = False


class _FakeResponse(object):

    def __init__(self, status_code, scopes=None):
        self.status_code = status_code
        if self.status_code == http_client.OK:
            self.content = json.dumps({'scope': ' '.join(scopes or [])})
        else:
            self.content = 'Error'
            self.info = str(http_client.responses[self.status_code])
            self.request_url = 'some-url'


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

    def _Args(self, credentials_format):
        return ['--credentials_format=' + credentials_format, 'userinfo.email']

    def testFormatBare(self):
        with mock.patch.object(oauth2l, '_FetchCredentials',
                               return_value=self.credentials,
                               autospec=True) as mock_credentials:
            output = _GetCommandOutput('fetch', self._Args('bare'))
            self.assertEqual(self.access_token, output)
            self.assertEqual(1, mock_credentials.call_count)

    def testFormatHeader(self):
        with mock.patch.object(oauth2l, '_FetchCredentials',
                               return_value=self.credentials,
                               autospec=True) as mock_credentials:
            output = _GetCommandOutput('fetch', self._Args('header'))
            header = 'Authorization: Bearer %s' % self.access_token
            self.assertEqual(header, output)
            self.assertEqual(1, mock_credentials.call_count)

    def testHeaderCommand(self):
        with mock.patch.object(oauth2l, '_FetchCredentials',
                               return_value=self.credentials,
                               autospec=True) as mock_credentials:
            output = _GetCommandOutput('header', ['userinfo.email'])
            header = 'Authorization: Bearer %s' % self.access_token
            self.assertEqual(header, output)
            self.assertEqual(1, mock_credentials.call_count)

    def testFormatJson(self):
        with mock.patch.object(oauth2l, '_FetchCredentials',
                               return_value=self.credentials,
                               autospec=True) as mock_credentials:
            output = _GetCommandOutput('fetch', self._Args('json'))
            output_lines = [l.strip() for l in output.splitlines()]
            expected_lines = [
                '"_class": "AccessTokenCredentials",',
                '"access_token": "%s",' % self.access_token,
            ]
            for line in expected_lines:
                self.assertIn(line, output_lines)
            self.assertEqual(1, mock_credentials.call_count)

    def testFormatJsonCompact(self):
        with mock.patch.object(oauth2l, '_FetchCredentials',
                               return_value=self.credentials,
                               autospec=True) as mock_credentials:
            output = _GetCommandOutput('fetch', self._Args('json_compact'))
            expected_clauses = [
                '"_class":"AccessTokenCredentials",',
                '"access_token":"%s",' % self.access_token,
            ]
            for clause in expected_clauses:
                self.assertIn(clause, output)
            self.assertEqual(1, len(output.splitlines()))
            self.assertEqual(1, mock_credentials.call_count)

    def testFormatPretty(self):
        with mock.patch.object(oauth2l, '_FetchCredentials',
                               return_value=self.credentials,
                               autospec=True) as mock_credentials:
            output = _GetCommandOutput('fetch', self._Args('pretty'))
            expecteds = ['oauth2client.client.AccessTokenCredentials',
                         self.access_token]
            for expected in expecteds:
                self.assertIn(expected, output)
            self.assertEqual(1, mock_credentials.call_count)

    def testFakeFormat(self):
        self.assertRaises(ValueError,
                          oauth2l._Format, 'xml', self.credentials)


class TestFetch(unittest.TestCase):

    def setUp(self):
        # Set up an access token to use
        self.access_token = 'ya29.abdefghijklmnopqrstuvwxyz'
        self.user_agent = 'oauth2l/1.0'
        self.credentials = oauth2client.client.AccessTokenCredentials(
            self.access_token, self.user_agent)

    def testNoScopes(self):
        output = _GetCommandOutput('fetch', [])
        self.assertEqual(
            'Error encountered in fetch operation: No scopes provided',
            output)

    def testScopes(self):
        expected_scopes = [
            'https://www.googleapis.com/auth/userinfo.email',
            'https://www.googleapis.com/auth/cloud-platform',
        ]
        token_info = {
            'email': 'user@gmail.com',
            'expires_in': 123,
            'scope': ' '.join(expected_scopes),
        }
        with mock.patch.object(apitools_base, 'GetCredentials',
                               return_value=self.credentials,
                               autospec=True) as mock_fetch:
            with mock.patch.object(oauth2l, '_GetTokenInfo',
                                   return_value=token_info,
                                   autospec=True) as mock_get_scopes:
                output = _GetCommandOutput(
                    'fetch', ['userinfo.email', 'cloud-platform'])
                self.assertIn(self.access_token, output)
                self.assertEqual(1, mock_fetch.call_count)
                args, _ = mock_fetch.call_args
                self.assertEqual(expected_scopes, args[-1])
                self.assertEqual(1, mock_get_scopes.call_count)
                self.assertEqual((self.access_token,),
                                 mock_get_scopes.call_args[0])

    def testCredentialsRefreshed(self):
        with mock.patch.object(apitools_base, 'GetCredentials',
                               return_value=self.credentials,
                               autospec=True) as mock_fetch:
            with mock.patch.object(oauth2l, '_TestToken',
                                   return_value=False,
                                   autospec=True) as mock_test:
                with mock.patch.object(self.credentials, 'refresh',
                                       return_value=None,
                                       autospec=True) as mock_refresh:
                    output = _GetCommandOutput('fetch', ['userinfo.email'])
                    self.assertIn(self.access_token, output)
                    self.assertEqual(1, mock_fetch.call_count)
                    self.assertEqual(1, mock_test.call_count)
                    self.assertEqual(1, mock_refresh.call_count)

    def testDefaultClientInfo(self):
        with mock.patch.object(apitools_base, 'GetCredentials',
                               return_value=self.credentials,
                               autospec=True) as mock_fetch:
            with mock.patch.object(oauth2l, '_TestToken',
                                   return_value=True,
                                   autospec=True) as mock_test:
                output = _GetCommandOutput('fetch', ['userinfo.email'])
                self.assertIn(self.access_token, output)
                self.assertEqual(1, mock_fetch.call_count)
                _, kwargs = mock_fetch.call_args
                self.assertEqual(
                    '1042881264118.apps.googleusercontent.com',
                    kwargs['client_id'])
                self.assertEqual(1, mock_test.call_count)

    def testMissingClientSecrets(self):
        self.assertRaises(
            ValueError,
            oauth2l.GetClientInfoFromFlags, '/non/existent/file')

    def testWrongClientSecretsFormat(self):
        client_secrets = os.path.join(
            os.path.dirname(__file__),
            'testdata/noninstalled_client_secrets.json')
        self.assertRaises(
            ValueError,
            oauth2l.GetClientInfoFromFlags, client_secrets)

    def testCustomClientInfo(self):
        client_secrets_path = os.path.join(
            os.path.dirname(__file__), 'testdata/fake_client_secrets.json')
        with mock.patch.object(apitools_base, 'GetCredentials',
                               return_value=self.credentials,
                               autospec=True) as mock_fetch:
            with mock.patch.object(oauth2l, '_TestToken',
                                   return_value=True,
                                   autospec=True) as mock_test:
                fetch_args = [
                    '--json=' + client_secrets_path,
                    'userinfo.email']
                output = _GetCommandOutput('fetch', fetch_args)
                self.assertIn(self.access_token, output)
                self.assertEqual(1, mock_fetch.call_count)
                _, kwargs = mock_fetch.call_args
                self.assertEqual('144169.apps.googleusercontent.com',
                                 kwargs['client_id'])
                self.assertEqual('awesomesecret',
                                 kwargs['client_secret'])
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
        response = _FakeResponse(http_client.OK, scopes=scopes)
        with mock.patch.object(apitools_base, 'MakeRequest',
                               return_value=response,
                               autospec=True) as mock_make_request:
            output = _GetCommandOutput('test', [self.access_token])
            self.assertEqual('', output)
            self.assertEqual(1, mock_make_request.call_count)

    def testBadResponseCode(self):
        response = _FakeResponse(http_client.BAD_REQUEST)
        with mock.patch.object(apitools_base, 'MakeRequest',
                               return_value=response,
                               autospec=True) as mock_make_request:
            output = _GetCommandOutput('info', [self.access_token])
            self.assertEqual('', output)
            self.assertEqual(1, mock_make_request.call_count)

    def testUnexpectedResponseCode(self):
        response = _FakeResponse(http_client.INTERNAL_SERVER_ERROR)
        with mock.patch.object(apitools_base, 'MakeRequest',
                               return_value=response,
                               autospec=True) as mock_make_request:
            output = _GetCommandOutput('info', [self.access_token])
            self.assertIn(str(http_client.responses[response.status_code]),
                          output)
            self.assertIn('Error encountered in info operation: HttpError',
                          output)
            self.assertEqual(1, mock_make_request.call_count)
