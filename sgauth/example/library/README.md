Google Authenticator(GA) Prototype
-------
## Installation

To install the Google Authenticator prototype, run:
```
go get github.com/google/oauth2l/sgauth/example/library
```
## Credentials
Currently Google Authenticator reads the service account JSON credential file from environment path:
1) Go to the [Pantheon UI](https://pantheon.corp.google.com/)
2) Enable the corresponding API if you haven't. (E.g. Service Management API in the example below)
2) Create the service account key.
2) Download the JSON credentials.
3) Set `$GOOGLE_APPLICATION_CREDENTIALS` to the JSON path.

## Command-line Usage
The demo main has the following usage pattern:
```
go run *.go protorpc|grpc --host {value} \
    [--aud {value}] [--scope {value}] [--api_name {value}] [--api_key {value}]
```
where:

- `protorpc|grpc` *[REQUIRED]* is the selector between ProtobufRPC and gRPC protocols.
- `--host` *[REQUIRED]* is the full host name of the API service. e.g. test-xxiang-library-example.sandbox.googleapis.com  
- `[--scope]` is the value of scope if you use OAuth2.0
- `[--aud]` is the value of audience if you use client-signed JWT token.
For more information about JWT token please read: [Service account authorization without OAuth](https://developers.google.com/identity/protocols/OAuth2ServiceAccount)
- `[--api_key]` is the Google API key.
- `[--api_name]` is the full API name. e.g. google.example.library.v1.LibraryService. This field is only required when `protorpc` mode is selected.

## Sample Usage

#### ProtoRPC
```
go run *.go protorpc --host library-example.googleapis.com  \
--api_name google.example.library.v1.LibraryService
```
#### gRPC
```
go run *.go grpc --host library-example.googleapis.com  \
--api_name google.example.library.v1.LibraryService 
```

Note: Both sample commands above uses JWT auth token by default. The audience is auto-computed based on the host and api_name.
You can always set the audience explicitly by using the `--aud` flag.

#### OAuth
To authorize with OAuth, you only need specify the extra `--scope` flag, for example:
```
go run *.go grpc --scope https://www.googleapis.com/auth/xapi.zoo \
--host library-example.googleapis.com 
```

#### API Key

To access the API with an API key:
```
go run *.go protorpc --host library-example.googleapis.com \
--api_name google.example.library.v1.LibraryService \
--api_key {API_KEY}
```
or if you wanna use gRPC:
```
go run *.go grpc --host library-example.googleapis.com  \
--api_key {API_KEY}
```
