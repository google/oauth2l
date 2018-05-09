oauth2l
-------

[![Build Status](https://travis-ci.org/google/oauth2l.svg?branch=master)](https://travis-ci.org/google/oauth2l)
[![Coverage](https://coveralls.io/repos/google/oauth2l/badge.svg?branch=master)](https://coveralls.io/r/google/oauth2l?branch=master)
[![PyPI](https://img.shields.io/pypi/v/google-oauth2l.svg)](https://pypi.python.org/pypi/google-oauth2l)
[![Versions](https://img.shields.io/pypi/pyversions/google-oauth2l.svg)](https://pypi.python.org/pypi/google-oauth2l)

`oauth2l` (pronounced "oauth tool") is a simple command-line tool for
working with
[Google OAuth 2.0](https://developers.google.com/identity/protocols/OAuth2).
Its primary use is to fetch and
print OAuth 2.0 access tokens, which can be used with other command-line
tools and shell scripts.

This tool also demonstrates how to design a simple and easy-to-use OAuth
2.0 client experience. If you need to reimplement this functionality in
another programming language, please use [Go OAuth2l](go/oauth2client)
as reference code.

## Overview

`oauth2l` supports all Google OAuth 2.0 authentication flows for both user
accounts and service accounts in different environments:

*   When running inside Google Compute Engine (GCE) and Google Container
    Engine (GKE), it uses the credentials of the current service account
    if it is available.

*   When running inside user context that has an active Google Cloud SDK
    (gcloud) session, it uses the current gcloud credentials.

*   When running with command option `--json xxx`, where `xxx` points to
    a JSON credential file downloaded from
    [Google Cloud Console](https://console.cloud.google.com/apis/credentials),
    `oauth2l` uses the file to start an OAuth session. The file can be
    either a service account key or an OAuth client ID.

*   When running with command option `--sso {email}`, it invokes an
    external `sso` command to retrieve Single Sign-on (SSO) access token.

NOTE: `oauth2l` caches the OAuth credentials in user's home directory to
avoid prompting user repeatedly.

## Install

```
# Mac only. Install `pip` first.
$ sudo easy_install pip

# Install `oauth2l` under the OS, typically "/usr/local/bin".
$ pip install google-oauth2l --upgrade

# If you see an error on OS X El Capitan or up, please try
$ pip install google-oauth2l --upgrade --ignore-installed

# Install `oauth2l` under the current user, typically "~/.local/bin" (on Linux)
# and "~/Library/Python/2.7/bin" (on Mac).
$ pip install --user google-oauth2l
```

## Command Options

### --json

Specifies an OAuth credential file, either an OAuth client ID or a Service
Account key, to start the OAuth flow. You can download the file from
[Google Cloud Console](https://console.cloud.google.com/apis/credentials).

```
$ oauth2l fetch --json ~/service_account.json cloud-platform
```

### --sso and --sso_cli

Using an external Single Sign-on (SSO) command to fetch OAuth token.
The command outputs an OAuth access token to its stdout. The default
command is for Google's corporate SSO. For example:

```
$ sso me@example.com scope1 scope2
```

Then use oauth2l with the SSO CLI:

```
$ oauth2l header --sso me@example.com --sso_cli /usr/bin/sso cloud-platform
$ oauth2l header --sso me@google.com cloud-platform
```

### --jwt

When this option is set and the json file specified in the `--json` option
is a service account key file, a JWT token signed by the service account
private key will be generated. When this option is set, no scope list is
needed but a single JWT audience must be provided. See how to construct the
audience [here](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#jwt-auth).

Example:

```
oauth2l fetch --jwt --json ~/service_account.json https://pubsub.googleapis.com/google.pubsub.v1.Publisher
```

## Commands

### fetch

Fetch and print an access token for the specified OAuth scopes. For example,
the following command prints access token for the following OAuth2 scopes:

*   https://www.googleapis.com/auth/userinfo.email
*   https://www.googleapis.com/auth/cloud-platform

```
$ oauth2l fetch userinfo.email cloud-platform
ya29.zyxwvutsrqpnmolkjihgfedcba

$ oauth2l fetch -f json userinfo.email cloud-platform
{
  "access_token": "ya29.zyxwvutsrqpnmolkjihgfedcba",
  "token_expiry": "2017-02-27T21:20:47Z",
  "user_agent": "oauth2l/1.0.0",
  ...
}
```

NOTE: the `-f` flag specifies the output format. The supported formats are:
bare (default), header, json, json_compact, pretty.

### header

The same as `fetch`, except the output is in HTTP header format:

```
$ oauth2l header userinfo.email
Authorization: Bearer ya29.zyxwvutsrqpnmolkjihgfedcba
```

The `header` command is designed to be easy to use with `curl`. For example,
the following command uses the PubSub API to list all PubSub topics.

```
$ curl -H "$(oauth2l header pubsub)" https://pubsub.googleapis.com/v1/projects/my-project-id/topics
```

If you need to call Google APIs frequently using `curl`, you can define a
shell alias for it. For example:

```
$ alias gcurl='curl -H "$(oauth2l header cloud-platform)" -H "Content-Type: application/json" '
$ gcurl 'https://pubsub.googleapis.com/v1/projects/my-project-id/topics'
```

### info

Print information about a valid token. This always includes the list of scopes
and expiration time. If the token has either the
`https://www.googleapis.com/auth/userinfo.email` or
`https://www.googleapis.com/auth/plus.me` scope, it also prints the email
address of the authenticated identity.

```
$ oauth2l info $(oauth2l fetch pubsub)
{
    "expires_in": 3599,
    "scope": "https://www.googleapis.com/auth/pubsub",
    "email": "user@gmail.com"
    ...
}
```

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
