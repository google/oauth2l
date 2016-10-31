# Go OAuth 2 Client

This package contains a simple and easy-to-use OAuth 2 client library.
It supports both 2-legged and 3-legged OAuth for most OAuth providers
without any change to the application code.

This library is intended to be a reference design for other programming
languages.

## Design

The basic design is to create an OAuth client using a JSON credential
file, then use the client to fetch OAuth tokens. Because the credential
file contains all necessary information about the OAuth client and the
OAuth provider, the library can work with different OAuth flows and
different OAuth providers. It allows developers to switch OAuth
client ID or service account or OAuth provider by using a different
JSON credential file without changing the application.

The general developer workflow is to download a JSON credential files
from an OAuth provider, such as
[Google API Console](https://console.developers.google.com) and
[Google Cloud Console](https://console.cloud.google.com), and pass
the file to the application. You can also manually create such files.
This client library will generate the OAuth access token for application
to use.

## Usage

This library has a simple interface, which you can use in the following
way:

    // Creates a client using the content of a JSON credential file.
    // The file can be either an OAuth client id or a service account
    // credential.
    client := oauth2client.NewClient(credential, nil)

    // Gets an access token for the specified OAuth scope.
    token := client.GetToken("https://www.googleapis.com/auth/cloud-platform")

## Command line tool

You can also install the companion `oauth2l` binary and use to fetch
OAuth access tokens to be used with other scrips and tools.

    # Install the binary.
    $ go get github.com/google/oauth2l/go/oauth2l

    # Print usage help.
    $ $GOPATH/bin/oauth2l

    # Fetch an access token.
    $ $GOPATH/bin/oauth2l --json cred.json header cloud-platform
