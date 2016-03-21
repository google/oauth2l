oauth2l
-------

`oauth2l` (pronounced "oauth tool") is a simple command-line tool that can be
used to interact with Google OAuth authentication system. Its primary use is
to fetch and print OAuth 2.0 access tokens, which can be used with other
command-line tools and shell scripts.

## Overview

`oauth2l` supports multiple OAuth 2.0 authentication flows for both user
accounts and service accounts, see below:

* When running inside Google Compute Engine (GCE), it uses the credentials of
the current GCE service account (if it exists).

* When running under user context that has an active Google Cloud SDK (gcloud)
session, it uses the credentials of the gcloud session.

* When running with command line flag `--json xxx`, where `xxx` points to a
JSON credential file -- either a service account or an oauth client id --
downloaded from Google API Console, `oauth2l` will use the JSON file to start
the OAuth session.

* Otherwise, `oauth2l` will use its own oauth client identity to start OAuth
session.

## Install

    pip install google-oauth2l

## Commands

### fetch

Print the access token for the specified oauth scopes. For example,
the following command prints access token for the following oauth scopes:

* https://www.googleapis.com/auth/userinfo.email
* https://www.googleapis.com/auth/cloud-platform

```
$ oauth2l fetch userinfo.email cloud-platform
```

### header

Print the access token (see above) in HTTP header format, for
example:

```
$ oauth2l header userinfo.email
Authorization: Bearer ya29.zyxwvutsrqpnmolkjihgfedcba
```

The `header` command is designed to be easy to use with `curl`. For example,
the following command uses the BigQuery API to list all projects.

```
$ curl -H "$(oauth2l header bigquery)" 'https://www.googleapis.com/bigquery/v2/projects'
```

### test

Validate a token. In particular, this sets an exit code of 0 for a valid
token and 1 otherwise, which can be useful in shell pipelines.

```
oauth2l test ya29.zyxwvutsrqpnmolkjihgfedcba
```
