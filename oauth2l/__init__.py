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

"""Command-line utility for fetching/inspecting credentials.

oauth2l (pronounced "oauthtool") is a small utility for fetching
credentials, or inspecting existing credentials. Here we demonstrate
some sample use:

    $ oauth2l fetch userinfo.email bigquery compute
    Fetched credentials of type:
      oauth2client.client.OAuth2Credentials
    Access token:
      ya29.abcdefghijklmnopqrstuvwxyz123yessirree
    $ oauth2l header userinfo.email
    Authorization: Bearer ya29.zyxwvutsrqpnmolkjihgfedcba
    $ oauth2l test thisisnotatoken
    <exit status: 1>
    $ oauth2l test ya29.zyxwvutsrqpnmolkjihgfedcba
    $ oauth2l info ya29.abcdefghijklmnopqrstuvwxyz123yessirree
    Scopes:
    * https://www.googleapis.com/auth/bigquery
    * https://www.googleapis.com/auth/compute
    * https://www.googleapis.com/auth/userinfo.email
    Expires in: 3520 seconds
    Email address: user@gmail.com

The `header` command is designed to be easy to use with `curl`:

    $ curl -H "$(oauth2l header bigquery)" \\
      'https://www.googleapis.com/bigquery/v2/projects'
    ... lists all projects ...

The token can also be printed in other formats, for easy chaining
into other programs:

    $ oauth2l fetch -f json_compact userinfo.email
    <one-line JSON object with credential information>
    $ oauth2l fetch -f bare drive
    ya29.suchT0kenManyCredentialsW0Wokyougetthepoint

"""

from __future__ import print_function

import argparse
import base64
import httplib2
import json
import logging
import os
import subprocess
import sys
import textwrap
import time
if sys.version_info[0] == 2:
  import httplib as http_client
else:
  import http.client as http_client  # pragma: NO COVER

from oauth2client import client
from oauth2client import GOOGLE_TOKEN_INFO_URI
from oauth2client import service_account
from oauth2client import tools
from oauth2client.contrib import multiprocess_file_storage
from OpenSSL import crypto
import pkg_resources

# We could use a generated client here, but it's used for precisely
# one URL, with one parameter and no worries about URL encoding. Let's
# go with simple.
_OAUTH2_TOKENINFO_TEMPLATE = (
    GOOGLE_TOKEN_INFO_URI + '?access_token={access_token}'
)

# Keep in sync with setup.py. (Currently just used for UserAgent
# tagging, so not critical.)
_OAUTH2L_VERSION = pkg_resources.get_distribution('google-oauth2l').version
_DEFAULT_USER_AGENT = 'oauth2l/' + _OAUTH2L_VERSION
# Prefix of Google OAuth scopes
_SCOPE_PREFIX = 'https://www.googleapis.com/auth/'

# Scopes defined by OpenID standard and does not have Google's URI prefix
_PREFIXLESS_SCOPES = ['profile', 'email', 'openid']

# We need to know the gcloud scopes in order to decide when to use the
# Application Default Credentials.
_GCLOUD_SCOPES = {
    _SCOPE_PREFIX + 'cloud-platform',
    _SCOPE_PREFIX + 'userinfo.email',
}

# CLI to retrieve OAuth 2 token via Google Corp SSO.
# The command should be called like:
# $ sso example@example.com scope1 scope2
# and the command returns a bare OAuth2 access token.
_SSO_CLI = '/google/data/ro/teams/oneplatform/sso'


class EmptyLoggingHandler(logging.Handler):
    def emit(self, record):
        pass  # pragma: NO COVER


logging.getLogger("oauth2client").addHandler(EmptyLoggingHandler())


def GetClientInfoFromFile(client_secrets):
    """Fetch client info from args."""
    client_secrets_path = os.path.expanduser(client_secrets)
    if not os.path.exists(client_secrets_path):
        raise ValueError(
            'Cannot find file: {0}'.format(client_secrets))
    with open(client_secrets_path) as client_secrets_file:
        client_secrets = json.load(client_secrets_file)
    if 'installed' not in client_secrets:
        raise ValueError('Provided client ID must be for an installed app')
    return client_secrets['installed']


def _ExpandScopes(scopes):
    return [s if s.startswith('https://') or s in _PREFIXLESS_SCOPES
            else _SCOPE_PREFIX + s for s in scopes]


def _PrettyJson(data):
    return json.dumps(data, sort_keys=True, indent=4, separators=(',', ': '))


def _CompactJson(data):
    return json.dumps(data, sort_keys=True, separators=(',', ':'))


def _AsText(text_or_bytes):
    if isinstance(text_or_bytes, bytes):
        return text_or_bytes.decode('utf8')
    return text_or_bytes


def _Format(fmt, credentials):
    """Format credentials according to fmt."""
    if fmt == 'bare':
        return credentials.access_token
    elif fmt == 'header':
        return 'Authorization: Bearer {}'.format(credentials.access_token)
    elif fmt == 'json':
        return _PrettyJson(json.loads(_AsText(credentials.to_json())))
    elif fmt == 'json_compact':
        return _CompactJson(json.loads(_AsText(credentials.to_json())))
    elif fmt == 'pretty':
        format_str = textwrap.dedent('\n'.join([
            'Fetched credentials of type:',
            '  {credentials_type.__module__}.{credentials_type.__name__}',
            'Access token:',
            '  {credentials.access_token}',
        ]))
        return format_str.format(credentials=credentials,
                                 credentials_type=type(credentials))
    raise ValueError('Unknown format: {0}'.format(fmt))

_FORMATS = set(('bare', 'header', 'json', 'json_compact', 'pretty'))


def _GetTokenInfo(access_token):
    """Return the list of valid scopes for the given token as a list."""
    url = _OAUTH2_TOKENINFO_TEMPLATE.format(access_token=access_token)
    h = httplib2.Http()
    response, content = h.request(url)
    if 'status' not in response:
        raise ValueError('No status in HTTP response')
    status_code = int(response['status'])
    if status_code not in [http_client.OK, http_client.BAD_REQUEST]:
        msg = (
            'Error making HTTP request to <{}>: status <{}>, '
            'content <{}>'.format(url, response['status'], content))
        raise ValueError(msg)
    if status_code == http_client.BAD_REQUEST:
        return {}
    return json.loads(_AsText(content))


def _TestToken(access_token):
    """Return True iff the provided access token is valid."""
    return bool(_GetTokenInfo(access_token))


def _ProcessJsonArg(args):
    """Get client_info and service_account_json_keyfile from args.

    This just reads args.json, and decides (based on contents) whether
    it's a client_secrets or a service_account key, and returns as
    appropriate.
    """
    filename = os.path.expanduser(args.json)
    if not filename:
        return '', ''
    with open(filename, 'rU') as f:
        try:
            contents = json.load(f)
        except ValueError:
            raise ValueError('Invalid JSON file: {}'.format(args.json))
    if contents.get('type', '') == 'service_account':
        return '', filename
    else:
        return filename, ''


def _GetApplicationDefaultCredentials(scopes):
    # There's a complication here: if the application default
    # credential returned to us is the token from the cloud SDK,
    # we need to ensure that our scopes are a subset of those
    # requested. In principle, we're a bit too strict here: eg if
    # a user requests just "bigquery", then the cloud-platform
    # scope suffices, but there's no programmatic way to check
    # this -- so we instead fail here.
    try:
        credentials = client.GoogleCredentials.get_application_default()
    except client.ApplicationDefaultCredentialsError:
        return None
    if credentials is not None:
        if not credentials.create_scoped_required():
            return credentials
        if set(scopes) <= _GCLOUD_SCOPES:
            return credentials.create_scoped(scopes)


def _GetCredentialsFilename(credentials_filename):
    return os.path.expanduser(credentials_filename or '~/.oauth2l.token')


def _GetCredentialStore(credentials_filename, key_id, scopes):
    credentials_filename = _GetCredentialsFilename(credentials_filename)
    storage_key = '{}#{}'.format(key_id, scopes)
    return multiprocess_file_storage.MultiprocessFileStorage(
        credentials_filename, storage_key)


def _GetCredentialsVia3LO(client_info, credentials_filename=None):
    credential_store = _GetCredentialStore(credentials_filename,
                                           client_info['client_id'],
                                           client_info['scope'])
    credentials = credential_store.get()
    if credentials is None or credentials.invalid:
        for _ in range(10):
            # If authorization fails, we want to retry, rather
            # than let this cascade up and get caught elsewhere.
            # If users want out of the retry loop, they can ^C.
            try:
                flow = client.OAuth2WebServerFlow(**client_info)
                flags, _ = tools.argparser.parse_known_args(
                    ['--noauth_local_webserver'])
                credentials = tools.run_flow(
                    flow, credential_store, flags)
                break
            except (SystemExit, client.FlowExchangeError) as e:
                # Here SystemExit is "no credential at all", and the
                # FlowExchangeError is "invalid" -- usually because
                # you reused a token.
                pass
            except httplib2.HttpLib2Error as e:
                raise ValueError(
                    'Communication error creating credentials:'
                    '{}'.format(e))
        else:
            credentials = None
    return credentials


def _GetCredentialForServiceAccount(json_keyfile, scopes,
                                    credentials_filename=None):
    with open(json_keyfile, 'r') as json_keyfile_obj:
        client_credentials = json.load(json_keyfile_obj)
    credential_store = _GetCredentialStore(credentials_filename,
                                           client_credentials['private_key_id'],
                                           ' '.join(sorted(scopes)))
    credentials = credential_store.get()
    if credentials is None or credentials.invalid:
        credentials = (
            service_account.ServiceAccountCredentials.from_json_keyfile_dict(
                client_credentials, scopes=scopes))
        credential_store.put(credentials)
        credentials.set_store(credential_store)
    return credentials

def _ConstructJwtCredential(json_keyfile, audience):
    with open(json_keyfile, 'r') as json_keyfile_obj:
        client_credentials = json.load(json_keyfile_obj)

    pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, client_credentials['private_key'])

    jwt_header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": client_credentials['private_key_id']
    }

    # Use time 1 minute before now to avoid clock skew with Google servers
    current_time = int(time.time()) - 60
    jwt_payload = {
        "iss": client_credentials['client_email'],
        "sub": client_credentials['client_email'],
        "aud": audience,
        "iat": current_time,
        "exp": current_time + 3600
    }

    jwt_header_base64 = base64.urlsafe_b64encode(json.dumps(jwt_header, separators=(',', ':')).encode('utf-8')).decode().strip('=')
    jwt_payload_base64 = base64.urlsafe_b64encode(json.dumps(jwt_payload, separators=(',', ':')).encode('utf-8')).decode().strip('=')
    jwt_base_string = jwt_header_base64 + '.' + jwt_payload_base64

    jwt_signature = base64.urlsafe_b64encode(crypto.sign(pkey, jwt_base_string, "sha256")).decode().strip('=')

    jwt = jwt_base_string + '.' + jwt_signature

    return client.AccessTokenCredentials(jwt, _DEFAULT_USER_AGENT)

def _FetchCredentialWithSso(sso_cli, sso_email, scopes):
    """Fetch a credential with access_token fetched from the sso CLI."""
    commands = [sso_cli, sso_email] + scopes
    try:
        process = subprocess.Popen(
            commands, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        result, _ = process.communicate()
        if process.returncode != 0:
            raise Exception
    except:
        raise ValueError('Failed to fetch OAuth token by SSO.')

    return client.AccessTokenCredentials(
        result.strip(), _DEFAULT_USER_AGENT)


def _FetchCredentials(args, client_info=None, credentials_filename=None):
    """Fetch a credential for the given sso/client_info and scopes."""
    scopes = _ExpandScopes(args.scope)
    if args.sso:
        return _FetchCredentialWithSso(
            args.sso_cli if args.sso_cli else _SSO_CLI, args.sso, scopes)

    client_secrets, service_account_json_keyfile = _ProcessJsonArg(args)

    if service_account_json_keyfile and args.jwt:
        if not scopes:
            raise ValueError('No audience provided')
        if len(scopes) > 1:
            raise ValueError('More than one audience provided')
        return _ConstructJwtCredential(service_account_json_keyfile, args.scope[0])

    if not scopes:
        raise ValueError('No scopes provided')
    credentials = None
    # If a service account or client secret file was provided, that
    # takes precedence.
    if service_account_json_keyfile:
        credentials = _GetCredentialForServiceAccount(
            service_account_json_keyfile, scopes,
            credentials_filename or args.credentials_filename)
    elif client_secrets:
        client_info = GetClientInfoFromFile(client_secrets)
        client_info['scope'] = ' '.join(sorted(scopes))
        client_info['user_agent'] = _DEFAULT_USER_AGENT
        credentials = _GetCredentialsVia3LO(
            client_info, credentials_filename or args.credentials_filename)
    else:
        # Try ADC
        credentials = _GetApplicationDefaultCredentials(scopes)

    if credentials is None:
        raise ValueError('Failed to fetch credentials')
    credentials.user_agent = _DEFAULT_USER_AGENT
    if credentials.access_token_expired or credentials.access_token is None:
        credentials.refresh(httplib2.Http())
    return credentials


def _Fetch(args):
    """Fetch a valid access token and display it."""
    credentials = _FetchCredentials(args)
    print(_Format(args.credentials_format.lower(), credentials))


def _Header(args):
    """Fetch an access token and display it formatted as an HTTP header."""
    print(_Format('header', _FetchCredentials(args)))


def _Info(args):
    """Print scope, expiration, and user info for this token."""
    tokeninfo = _GetTokenInfo(args.access_token)
    if not tokeninfo:
        return 1
    if args.format == 'json':
        print(_PrettyJson(tokeninfo))
    else:
        print(_CompactJson(tokeninfo))


def _Reset(args):
    credentials_filename = _GetCredentialsFilename(args.credentials_filename)
    if os.path.exists(credentials_filename):
      os.remove(credentials_filename)


def _Test(args):
    """Test an access token. Exits with 0 if valid, 1 otherwise."""
    return 1 - (_TestToken(args.access_token))


def _GetParser():

    shared_flags = argparse.ArgumentParser(add_help=False)
    shared_flags.add_argument(
        '--credentials_filename',
        default='',
        help='(optional) Filename for fetching/storing credentials.')
    shared_flags.add_argument(
        '--json',
        default='',
        help=('JSON file downloaded from Google Developer Console. '
              'Can be either client ID/secret or a JSON service account key.'))
    shared_flags.add_argument(
        '--sso_cli',
        default='',
        help=('(optional) CLI for retrieving OAuth token via SSO. If not '
              'provided, the Google Corp CLI is used (only work on Google '
              'internal network).'))
    shared_flags.add_argument(
        '--sso',
        default='',
        help=('Email address for getting OAuth token with SSO.'))
    shared_flags.add_argument(
        '--jwt',
        action='store_true',
        help=('Use specified service account json key to generate a JWT token instead of access token.'))

    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest='command')

    # fetch
    fetch = subparsers.add_parser('fetch', help=_Fetch.__doc__,
                                  parents=[shared_flags])
    fetch.set_defaults(func=_Fetch)
    fetch.add_argument(
        '-f', '--credentials_format',
        default='bare', choices=sorted(_FORMATS),
        help='Output format for token.')
    fetch.add_argument(
        'scope',
        nargs='*',
        help='Scope to fetch. May be provided multiple times.')

    # header
    header = subparsers.add_parser('header', help=_Header.__doc__,
                                   parents=[shared_flags])
    header.set_defaults(func=_Header)
    header.add_argument(
        'scope',
        nargs='*',
        help='Scope to header. May be provided multiple times.')

    # reset
    reset = subparsers.add_parser('reset', help=_Reset.__doc__,
                                   parents=[shared_flags])
    reset.set_defaults(func=_Reset)

    # info
    info = subparsers.add_parser('info', help=_Info.__doc__,
                                 parents=[shared_flags])
    info.set_defaults(func=_Info)
    info.add_argument(
        '-f', '--format',
        default='json', choices=('json', 'json_compact'),
        help='Output format for info.')
    info.add_argument(
        'access_token',
        help=('Info for this token will be printed.'))

    # test
    test = subparsers.add_parser('test', help=_Test.__doc__,
                                 parents=[shared_flags])
    test.set_defaults(func=_Test)
    test.add_argument(
        'access_token',
        help='Access token to test.')

    return parser


def main(argv=None):
    argv = argv or sys.argv
    # Invoke the newly created parser.
    args = _GetParser().parse_args(argv[1:])
    try:
        exit_code = args.func(args)
    except BaseException as e:
        print('Error encountered in {0} operation: {1}'.format(
            args.command, e))
        return 1
    return exit_code


if __name__ == '__main__':
    sys.exit(main(sys.argv))  # pragma: NO COVER
