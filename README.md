oauth2l
-------

[![Build Status](https://travis-ci.org/google/oauth2l.svg?branch=master)](https://travis-ci.org/google/oauth2l)
[![Coverage](https://coveralls.io/repos/google/oauth2l/badge.svg?branch=master)](https://coveralls.io/r/google/oauth2l?branch=master)
[![PyPI](https://img.shields.io/pypi/v/google-oauth2l.svg)](https://pypi.python.org/pypi/google-oauth2l)
[![Versions](https://img.shields.io/pypi/pyversions/google-oauth2l.svg)](https://pypi.python.org/pypi/google-oauth2l)

`oauth2l` (pronounced "oauth tool") is a simple command-line tool for
interacting with Google OAuth system. Its primary use is to fetch and
print OAuth 2.0 access tokens, which can be used with other command-line
tools and shell scripts.

If you need to reimplement this functionality in another programming
language, see [Go OAuth2l](go/oauth2client) for reference.

## Overview

`oauth2l` supports multiple OAuth 2.0 authentication flows for both user
accounts and service accounts:

* When running inside Google Compute Engine (GCE) and Google Container
Engine (GKE), it uses the credentials of the current GCE service account
(if it exists).

* When running inside user context that has an active Google Cloud SDK
(gcloud) session, it uses the gcloud credential.

* When running with command line flag `--json xxx`, where `xxx` points to a
JSON credential file -- either a service account or an OAuth client ID --
downloaded from Google API Console, `oauth2l` will use the JSON file to start
the OAuth session.

NOTE: `oauth2l` will cache the OAuth credential until its expiration to avoid
prompting user repeatedly.

## Install

```
# Mac only. Install pip.
$ sudo easy_install pip

# Install oauth2l under OS, typically "/usr/local/bin".
$ pip install google-oauth2l --upgrade

# If you see an error on OS X El Capitan or up, please try
$ pip install google-oauth2l --upgrade --ignore-installed

# Install oauth2l under current user, typically "~/.local/bin" (on Linux)
# and "~/Library/Python/2.7/bin" (on Mac).
$ pip install --user google-oauth2l
```

## Commands

### fetch

Fetch and print an access token for the specified OAuth scopes. For example,
the following command prints access token for the following OAuth2 scopes:

* https://www.googleapis.com/auth/userinfo.email
* https://www.googleapis.com/auth/cloud-platform

```
$ oauth2l fetch userinfo.email cloud-platform
ya29.zyxwvutsrqpnmolkjihgfedcba
```
Note the `-f` flag specifies output format. Supported formats are: 
bare, header, json, json_compact, pretty(default).

```
oauth2l fetch -f json userinfo.email cloud-platform
{
  "access_token": "ya29.zyxwvutsrqpnmolkjihgfedcba",
  "token_expiry": "2017-02-27T21:20:47Z",
  "user_agent": "oauth2l/1.0.0",
  ...
}
```

You can also fetch an OAuth token by using the secret json file downloaded from
[Google Cloud Console](https://console.cloud.google.com/apis/credentials).
```
$ oauth2l fetch --json service_account.json cloud-platform
ya29.zyxwvutsrqpnmolkjihgfedcba

```

### header

Same as `fetch`, except that we print the token in HTTP header format:

```
$ oauth2l header userinfo.email
Authorization: Bearer ya29.zyxwvutsrqpnmolkjihgfedcba
```

The `header` command is designed to be easy to use with `curl`. For example,
the following command uses the BigQuery API to list all projects.

```
$ curl -H "$(oauth2l header bigquery)" 'https://www.googleapis.com/bigquery/v2/projects'
```

If you need to call Google APIs frequently using the `header` command, you
can define a shell alias for it, for example:

```
$ alias gcurl='curl -H "$(oauth2l header cloud-platform)" -H "Content-Type: application/json" '
$ gcurl 'https://www.googleapis.com/bigquery/v2/projects'
```

### info

Print information about a valid token. This always includes the list of scopes
and expiration time. If the token has either the
`https://www.googleapis.com/auth/userinfo.email` or
`https://www.googleapis.com/auth/plus.me` scope, it also prints the email
address of the authenticated identity.

```
$ oauth2l info $(oauth2l fetch -f bare bigquery)
{
    "expires_in": 3599,
    "scope": "https://www.googleapis.com/auth/bigquery",
    "email": "user@gmail.com"
}
```

NOTE: The actual output may have a few more fields.

### test

Test a token. This sets an exit code of 0 for a valid token and 1 otherwise,
which can be useful in shell pipelines.

```
$ oauth2l test ya29.zyxwvutsrqpnmolkjihgfedcba
$ echo $?
0
$ oauth2l test ya29.justkiddingmadethisoneup
$ echo $?
1
```

### reset

Reset all tokens cached locally. We cache previously retrieved tokens in the
file `~/.oauth2l.token`.

```
$ oauth2l reset
```

## Options

### `--json`

Specifies an OAuth credential file, either OAuth client ID or Service Account
key, to start the OAuth flow. 
You can download the file from
[Google Cloud Console](https://console.cloud.google.com/apis/credentials).

```
$ oauth2l fetch --json ~/service_account.json cloud-platform
```

### `--sso` and `--sso_cli`

A single sign-on (SSO) command to fetch OAuth token. 
The command outputs an OAuth access token to its stdout. 
The default command is for Google's corporate SSO.
It works like:

```
$ sso me@example.com scope1 scope2
```

Then use oauth2l with the SSO CLI:

```
$ oauth2l header --sso me@example.com --sso_cli /usr/bin/sso cloud-platform
$ oauth2l header --sso me@google.com cloud-platform
```
