oauth2l
-------

`oauth2l` (pronounced "oauth tool") is a simple command-line tool for
working with
[Google OAuth 2.0](https://developers.google.com/identity/protocols/OAuth2)
written in Go.
Its primary use is to fetch and
print OAuth 2.0 access tokens, which can be used with other command-line
tools and shell scripts.

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

## Quickstart

You will need to meet the following requirement to use this tool:

__Minimum requirements:__
- The tool is only available for _Linux_ or _Mac_
- _Go 1.10.3_ or higher

__Nice to have:__
- Add your _$GOPATH/bin_ into your _$PATH_ ([instuctions](
https://github.com/golang/go/wiki/GOPATH))


```bash
# Get the package from Github
$ go get github.com/google/oauth2l/go/oauth2l

# Install the package into your $GOPATH/bin/
$ go install github.com/google/oauth2l/go/oauth2l

# Fetch the access token from your credentials with cloud-platform scope
$ ~/go/bin/oauth2l fetch --json ~/your_credentials.json cloud-platform

# Or you can run if you $GOPATH/bin is already in your $PATH
$ oauth2l fetch --json ~/your_credentials.json cloud-platform
```

## Command Options

### --json

Specifies an OAuth credential file, either an OAuth client ID or a Service
Account key, to start the OAuth flow. You can download the file from
[Google Cloud Console](https://console.cloud.google.com/apis/credentials).

```bash
$ oauth2l fetch --json ~/service_account.json cloud-platform
```

### --sso and --sso_cli

Using an external Single Sign-on (SSO) command to fetch OAuth token.
The command outputs an OAuth access token to its stdout. The default
command is for Google's corporate SSO. For example:

```bash
$ sso me@example.com scope1 scope2
```

Then use oauth2l with the SSO CLI:

```bash
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

```bash
oauth2l fetch --jwt --json ~/service_account.json https://pubsub.googleapis.com/google.pubsub.v1.Publisher
```

## Commands

### fetch

Fetch and print an access token for the specified OAuth scopes. For example,
the following command prints access token for the following OAuth2 scopes:

*   https://www.googleapis.com/auth/userinfo.email
*   https://www.googleapis.com/auth/cloud-platform

```bash
$ oauth2l fetch userinfo.email cloud-platform
ya29.zyxwvutsrqpnmolkjihgfedcba
```

### header

The same as `fetch`, except the output is in HTTP header format:

```bash
$ oauth2l header userinfo.email
Authorization: Bearer ya29.zyxwvutsrqpnmolkjihgfedcba
```

The `header` command is designed to be easy to use with `curl`. For example,
the following command uses the PubSub API to list all PubSub topics.

```bash
$ curl -H "$(oauth2l header pubsub)" https://pubsub.googleapis.com/v1/projects/my-project-id/topics
```

If you need to call Google APIs frequently using `curl`, you can define a
shell alias for it. For example:

```bash
$ alias gcurl='curl -H "$(oauth2l header cloud-platform)" -H "Content-Type: application/json" '
$ gcurl 'https://pubsub.googleapis.com/v1/projects/my-project-id/topics'
```

### info

Print information about a valid token. This always includes the list of scopes
and expiration time. If the token has either the
`https://www.googleapis.com/auth/userinfo.email` or
`https://www.googleapis.com/auth/plus.me` scope, it also prints the email
address of the authenticated identity.

```bash
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

```bash
$ oauth2l test ya29.zyxwvutsrqpnmolkjihgfedcba
$ echo $?
0
$ oauth2l test ya29.justkiddingmadethisoneup
$ echo $?
1
```
