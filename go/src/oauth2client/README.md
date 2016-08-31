# Go OAuth 2 Client

This package contains a simple and easy-to-use OAuth 2 client library.
It supports both 2-legged and 3-legged OAuth for most OAuth providers
without requiring any code change to your applications.

It is intended to be a reference design for other programming languages.

## Design

The basic design is to create an OAuth client using a JSON credential
file, and use the client to fetch OAuth access tokens. Because the
credential file contains all necessary information -- such as client
id, client secret, auth URL, token URL -- the library itself does not
refer to any application or any OAuth provider. It allows a user to
switch application identity or OAuth provider by simply feeding a
different JSON credential file to an application.

Normally, you can download the JSON credential files from places, such
as [Google API Console](https://console.developers.google.com) and
[Google Cloud Console](https://console.cloud.google.com). You can also
manually create such files.

## Usage

This library has a very simple interface, which you can use in the
following way:

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
    $ go get github.com/google/oauth2l/go/src/oauth2l

    # Print usage help.
    $ $GOPATH/bin/oauth2l

    # Fetch an access token.
    $ $GOPATH/bin/oauth2l header --json cred.json cloud-platform
