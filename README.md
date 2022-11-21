## oauth2l

`oauth2l` (pronounced "oauth tool") is a simple command-line tool for
working with
[Google OAuth 2.0](https://developers.google.com/identity/protocols/OAuth2)
written in Go. Its primary use is to fetch and print OAuth 2.0 access
tokens, which can be used with other command-line tools and shell scripts.

## Overview

`oauth2l` supports all Google OAuth 2.0 authentication flows for both user
accounts and service accounts in different environments:

- When running inside Google Compute Engine (GCE) and Google Kubernetes
  Engine (GKE), it uses the credentials of the current service account
  if it is available.

- When running inside user context that has an active Google Cloud SDK
  (gcloud) session, it uses the current gcloud credentials.

- When running with command option `--credentials xxx`, where `xxx` points to
  a JSON credential file downloaded from
  [Google Cloud Console](https://console.cloud.google.com/apis/credentials),
  `oauth2l` uses the file to start an OAuth session. The file can be
  either a service account key or an OAuth client ID.

- When running with command option `--type jwt --audience xxx` and a service
  account key, a JWT token signed by the service account key will be generated.

- When running with command option `--type sso --email xxx`, `oauth2l` invokes
  an external `sso` command to retrieve Single Sign-on (SSO) access token.

- By default, retrieved tokens will be cached and stored in "~/.oauth2l".
  The cache location can be overridden via `--cache xxx`. To disable
  caching, set cache location to empty ("").

## Quickstart

### Pre-compiled binaries

Pre-built binaries are available for Darwin (Mac OS X), Linux, and Windows. You
can download a build for any tag, for example:

| OS      | Link                                                            |
| ------- | --------------------------------------------------------------- |
| Darwin  | https://storage.googleapis.com/oauth2l/latest/darwin_amd64.tgz  |
| Linux   | https://storage.googleapis.com/oauth2l/latest/linux_amd64.tgz   |
| Windows | https://storage.googleapis.com/oauth2l/latest/windows_amd64.tgz |

Substitute "latest" for any tag version you'd like, removing any leading "v"
prefix.

### Homebrew (Mac OS X)

On Mac OS X, you can install `oauth2l` via [Homebrew](https://brew.sh):

```bash
$ brew install oauth2l
```

Note that new releases may not be immediately available via Homebrew because
updating is a manual process.

### Docker

An official Docker image is available at:

```text
gcr.io/oauth2l/oauth2l
```

You can run this directly:

```sh
$ docker run -it gcr.io/oauth2l/oauth2l header cloud-platform
```

Or use it to inject into an existing container:

```dockerfile
FROM my-awesome-container
COPY --from gcr.io/oauth2l/oauth2l /bin/oauth2l /bin/oauth2l
```

Like the binary releases, the container images are tagged to match the
repository tags (without the leading "v"). For master builds, use the "latest"
tag.

### Everywhere else

On other systems, you need to meet the following requirements to use this tool:

**Minimum requirements:**

- The tool is only available for _Linux_ or _Mac_
- _Go 1.10.3_ or higher

**Nice to have:**

- Add your _\$GOPATH/bin_ into your _\$PATH_ ([instructions](https://github.com/golang/go/wiki/GOPATH))

```bash
# Get the package from Github
$ git clone https://github.com/google/oauth2l
$ cd oauth2l

# Install the package into your $GOPATH/bin/
$ make dev

# Fetch the access token from your credentials with cloud-platform scope
$ ~/go/bin/oauth2l fetch --credentials ~/your_credentials.json --scope cloud-platform

# Or you can run if you $GOPATH/bin is already in your $PATH
$ oauth2l fetch --credentials ~/your_credentials.json --scope cloud-platform
```

## Commands

### fetch

Fetch and print an access token for the specified OAuth scopes. For example,
the following command prints access token for the following OAuth2 scopes:

- https://www.googleapis.com/auth/userinfo.email
- https://www.googleapis.com/auth/cloud-platform

```bash
$ oauth2l fetch --scope userinfo.email,cloud-platform
ya29.zyxwvutsrqpnmolkjihgfedcba
```

### header

The same as `fetch`, except the output is in HTTP header format:

```bash
$ oauth2l header --scope cloud-platform
Authorization: Bearer ya29.zyxwvutsrqpnmolkjihgfedcba
```

The `header` command is designed to be easy to use with the `curl` CLI. For
example, the following command uses the PubSub API to list all PubSub topics.

```bash
$ curl -H "$(oauth2l header --scope pubsub)" https://pubsub.googleapis.com/v1/projects/my-project-id/topics
```

To send an API request using domain-wide delegation (DwD), for example, to
list `user@example.com`'s Gmail labels:

```bash
$ curl -H "$(oauth2l header --email user@example.com --credentials service_account_credentials.json --scope https://www.googleapis.com/auth/gmail.labels)" https://gmail.googleapis.com/gmail/v1/users/me/labels
```

### curl

This is a shortcut command that fetches an access token for the specified OAuth
scopes and uses the token to make a curl request (via 'usr/bin/curl' by
default). Additional flags after "--" will be treated as curl flags.

```bash
$ oauth2l curl --scope cloud-platform,pubsub --url https://pubsub.googleapis.com/v1/projects/my-project-id/topics -- -i
```

To send an API request using domain-wide delegation (DwD), for example, to
list `user@example.com`'s Gmail labels:

```bash
$ oauth2l curl --email user@example.com --credentials service_account_credentials.json --scope https://www.googleapis.com/auth/gmail.labels --url https://gmail.googleapis.com/gmail/v1/users/me/labels
```


### info

Print information about a valid token. This always includes the list of scopes
and expiration time. If the token has either the
`https://www.googleapis.com/auth/userinfo.email` or
`https://www.googleapis.com/auth/plus.me` scope, it also prints the email
address of the authenticated identity.

```bash
$ oauth2l info --token $(oauth2l fetch --scope pubsub)
{
    "expires_in": 3599,
    "scope": "https://www.googleapis.com/auth/pubsub",
    "email": "user@gmail.com"
    ...
}
```

### test

Test a token. This sets an exit code of 0 for a valid token and 1 otherwise,
which can be useful in shell pipelines. It also prints the exit code.

```bash
$ oauth2l test --token ya29.zyxwvutsrqpnmolkjihgfedcba
0
$ echo $?
0
$ oauth2l test --token ya29.justkiddingmadethisoneup
1
$ echo $?
1
```

### reset

Reset all tokens cached locally. We cache previously retrieved tokens in the
file `~/.oauth2l` by default.

```bash
$ oauth2l reset
```

### web

Locally deploys and launches the OAuth2l Playground web application in a browser. If the web application packages are not yet installed, it will be installed under `~/.oauth2l-web` by default. See Command Options section for all supported options for the web command.

Note that a local installation of Docker and docker-compose tool is required in order to support this feature. For most platforms, Docker can be installed by following the instructions [here](https://docs.docker.com/get-docker/). For Google workstations, follow special installation procedures at "go/installdocker". The web feature is currently experimental and will be improved in the future.

```bash
$ oauth2l web
```

## Command Options

### --help

Prints help messages for the main program or a specific command.

```bash
$ oauth2l --help
```

```bash
$ oauth2l fetch --help
```

### --credentials

Specifies an OAuth credential file (either an OAuth client ID or a Service
Account key) to start the OAuth flow. You can download the file from
[Google Cloud Console](https://console.cloud.google.com/apis/credentials).

```bash
$ oauth2l fetch --credentials ~/service_account.json --scope cloud-platform
```

If this option is not supplied, it will be read from the environment variable
GOOGLE_APPLICATION_CREDENTIALS. For more information, please read
[Getting started with Authentication](https://cloud.google.com/docs/authentication/getting-started).

```bash
$ export GOOGLE_APPLICATION_CREDENTIALS="~/service_account.json"
$ oauth2l fetch --scope cloud-platform
```

When using an OAuth client ID file, the following applies: 
 
If the first `redirect_uris` in the `--credentials client_id.json` is set to `urn:ietf:wg:oauth:2.0:oob`,
the 3LO out of band flow is activated. NOTE: 3LO out of band flow has been deprecated and will stop working entirely in Oct 2022.

If the first `redirect_uris` in the `--credentials client_id.json` is set to `http://localhost[:PORT]`,
the 3LO loopback flow is activated. When the port is omitted, an available port will be used to spin up the localhost.
When a port is provided, oauth2l will attempt to use such port. If the port cannot be used, oauth2l will stop.  

### --type

The authentication type. The currently supported types are "oauth", "jwt", or
"sso". Defaults to "oauth".

#### oauth

When oauth is selected, the tool will fetch an OAuth access token through one
of two different flows. If service account key is provided, 2-legged OAuth flow
is performed. If OAuth Client ID is provided, 3-legged OAuth flow is performed,
which requires user consent. Learn about the different types of OAuth
[here](https://developers.google.com/identity/protocols/OAuth2).

```bash
$ oauth2l fetch --type oauth --credentials ~/client_credentials.json --scope cloud-platform
```

#### jwt

When jwt is selected and the json file specified in the `--credentials` option
is a service account key file, a JWT token signed by the service account private
key will be generated. Either `--audience` or `--scope` must be specified for
this option. See how to construct the audience [here](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#jwt-auth).

- With audience:
  ```bash
  $ oauth2l fetch --type jwt --credentials ~/service_account.json --audience https://pubsub.googleapis.com/
  ```

- With scope:
  ```bash
  $ oauth2l fetch --type jwt --credentials ~/service_account.json --scope cloud-platform
  ```

#### sso

When sso is selected, the tool will use an external Single Sign-on (SSO)
CLI to fetch an OAuth access token. The default SSO CLI only works with
Google's corporate SSO. An email is required in addition to scope.

To use oauth2l with the default SSO CLI:

```bash
$ oauth2l header --type sso --email me@google.com --scope cloud-platform
```

To use oauth2l with a custom SSO CLI:

```bash
$ oauth2l header --type sso --ssocli /usr/bin/sso --email me@google.com --scope cloud-platform
```

Note: The custom SSO CLI should have the following interface:

```bash
$ /usr/bin/sso me@example.com scope1 scope2
```

### --scope

The scope(s) that will be authorized by the OAuth access token. Required for
oauth and sso authentication types. When using multiple scopes, provide the
the parameter as a comma-delimited list and do not include spaces. (Alternatively,
multiple scopes can be specified as a space-delimited string surrounded in quotes.)

```bash
$ oauth2l fetch --scope cloud-platform,pubsub
```

### --sts

If true, exchanges the fetched access token with an STS token using Google's
Secure Token Service. You may optionally specify claims to be embedded into
the STS token. The currently supported STS claims are "audience" and "quota_project".

This option is compatible with oauth and sso authentication types,
but is currently incompatible with jwt.

```bash
$ oauth2l fetch --sts --audience https://pubsub.googleapis.com/ --quota_project quotaprojectid
```

### --audience

The single audience to include in the signed JWT token. Required for jwt
authentication type. Can also be used for STS.

```bash
$ oauth2l fetch --type jwt --audience https://pubsub.googleapis.com/
```

### --quota_project

The quota project to include in the STS claim. Used for quota and billing override.

```bash
$ oauth2l fetch --sts --quota_project quotaprojectid
```

### --email

The email associated with SSO. Required for sso authentication type.

```bash
$ oauth2l fetch --type sso --email me@google.com --scope cloud-platform
```

The email parameter can be also used to specify a user email account for domain-wide
delegation when authenticating with Service Account credentials.

```bash
$ oauth2l fetch --credentials ~/service_account.json --scope cloud-platform --email user@google.com
```

### --ssocli

Path to SSO CLI. For optional use with "sso" authentication type.

```bash
$ oauth2l fetch --type sso --ssocli /usr/bin/sso --email me@google.com --scope cloud-platform
```

### --cache

Path to token cache file. Disables caching if set to empty (""). Defaults to ~/.oauth2l if not configured.

```bash
$ oauth2l fetch --cache ~/different_path/.oauth2l --scope cloud-platform
```

### --refresh

If true, attempt to refresh expired access token (from the cache) using refresh token instead of re-authorizing.

```bash
$ oauth2l fetch --credentials ~/client_credentials.json --scope cloud-platform --refresh
```

### --impersonate-service-account

If specified, exchanges the fetched User access token with a Service Account access token using Google's
IAM Service. The Service Account parameter can be specified as an ID or an email. Note that at least
one of "cloud-platform" or "iam" must be included in the scope parameter. Learn more about Service Account
Impersonation [here](https://cloud.google.com/iam/docs/impersonating-service-accounts).

```bash
$ oauth2l fetch --credentials ~/client_credentials.json --scope cloud-platform,pubsub --impersonate-service-account 113258942105700140798
```

### --disableAutoOpenConsentPage

Disables the feature to automatically open the consent page in 3LO loopback flows.
When this option is used, the user will be provided with a URL to manually interact with the consent page.
This flag does not take any arguments. Simply add the option to disable this feature.

```bash
$ oauth2l fetch --credentials ~/client_credentials.json --disableAutoOpenConsentPage --consentPageInteractionTimeout 60 --consentPageInteractionTimeoutUnits seconds --scope cloud-platform
```

### --consentPageInteractionTimeout

Amount of time to wait for a user to interact with the consent page in 3LO loopback flows.
Once the time has lapsed, the localhost at the `redirect_uri` will no longer be available.  
Its default value is 2. See `--consentPageInteractionTimeoutUnits` to change the units.

### --consentPageInteractionTimeoutUnits

Units of measurement to use when `--consentPageInteractionTimeout` is set.
Its default value is `minutes`. Valid inputs are `seconds` and `minutes`.
This option only affects 3LO loopback flows.

### fetch --output_format

Token's output format for "fetch" command. One of bare, header, json, json_compact, pretty, or refresh_token. Default is bare.

```bash
$ oauth2l fetch --output_format pretty --scope cloud-platform
```

### curl --url

URL endpoint for curl request. Required for "curl" command.

```bash
$ oauth2l curl --scope cloud-platform --url https://pubsub.googleapis.com/v1/projects/my-project-id/topics
```

### curl --curlcli

Path to curl CLI. For optional use with "curl" command.

```bash
$ oauth2l curl --curlcli /usr/bin/curl --type sso --email me@google.com --scope cloud-platform --url https://pubsub.googleapis.com/v1/projects/my-project-id/topics
```

### web --stop

Stops the OAuth2l Playground web app.

```bash
$ oauth2l web --stop
```

### web --directory

Installs OAuth2l-web packages to a specfic directory. If this option is used, it should be provided again for future executions of the web command, such as stopping and restarting the web app.

```
$ oauth2l web --directory your/new/directory
```

## Previous Version

The previous version of `oauth2l` was written in Python and it is located
at the [python](/python) directory. The Python version is deprecated because
it depends on a legacy auth library and contains some features that are
no longer best practice. Please switch to use the Go version instead.
