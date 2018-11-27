Google Authenticator
======

This is the initial repository of Google Authenticator --- a _shard-agnostic_ client library that
 provides a unified future-proof interface for Google API authentication.

The project is still at very early stage so __everything is subject to change__.

Concept
-------
Google Authenticator is a future-proof client library that aims 
to simplify the developer experience with Google API authentication. 


Comparing with existing Google Authentication Libraries, it bring the following advantages:

- __Lightweight concept:__ Decouple the authentication client from underlying workflow.
Application only provides credentials and then make the API call.
As a result, developers should only need minimum knowledge about the authentication workflow.

- __Unified interface:__ The developer only needs to provide a general settings object. This unified credential object
 is an extensible structure that can contain arbitrary type of credentials.
 
Quickstart
----------

To use the authenticator library in your application simply import the package in your source
code:

```go
import "github.com/google/oauth2l/sgauth"
```

To use the authenticator to call Google APIs, simply create a authenticator settings object with
the credentials supported by Google APIs, and use the settings to create the client.
For example, to call Google API with HTTP and API key:

```go
import "github.com/google/oauth2l/sgauth"

// Create the settings with pasted API key.
settings := &sgauth.Settings{
                APIKey: "YOUR_API_KEY",
            }
// Create the HTTP client with the settings using authenticator.
http, err := sgauth.NewHTTPClient(ctx, createSettings(args))
if err != nil {
	// Call Google API here
}
```

Credentials
-----------

To authenticate against Google API, users need to provide required credentials.
The authenticator takes a general settings object that supports multiple types of credentials:

- __Service account JSON__: You can explicitly set the JSON string downloaded from Pantheon so
it can be used by either OAuth or JWT auth flow. If you prefer to use the JWT token authentication
flow, the `aud` value has to be provided. Alternatively, you can use the OAuth flow where you
need to specify the `scope` value.

- __API Key__: The Google API key.

- __Application Default Credentials__: If no credentials set explicitly, Google Authenticator
will try to look for your service account JSON file at the default path --- the path specified
by the `$GOOGLE_APPLICATION_CREDENTIAL` environment variable.

- __Authorized User__: If no above conditions are defined and you can still auth to google by genearating
ADC with command `gcloud auth application-default login`. This will store ADC at wellknown path 
`~/.config/gcloud/application_default_credentials.json`

Protocols
---------

Google authenticator supports three protocols which are widely supported by Google APIs:
__REST, gRPC, ProtoRPC__

To use the library calling __REST APIs__, simply create a HTTP client:
```go
import "github.com/google/oauth2l/sgauth"

// Create the settings
settings := &sgauth.Settings{
                // Config your credential settings
            }
// Create the HTTP client with the settings using authenticator.
http, err := sgauth.NewHTTPClient(ctx, createSettings(args))
if err != nil {
	// Call REST Google API here
}
```

Or you can use the library with a __gRPC API client__:

```go
import "github.com/google/oauth2l/sgauth"

// Create the settings
settings := &sgauth.Settings{
                // Config your credential settings
            }
// Create the gRPC connection with the settings using authenticator.
conn, err := sgauth.NewGrpcConn(ctx, createSettings(args), "YOUR_HOST", "YOUR_PORT")
if err != nil {
    return nil, err
}
client := library.NewLibraryServiceClient(conn)
```

To use the library calling __ProtoRPC APIs__:
```go
import "github.com/google/oauth2l/sgauth"
import "github.com/wora/protorpc/client"

// Create the settings
settings := &sgauth.Settings{
                // Config your credential settings
            }
// Create the HTTP client with the settings using authenticator.
http, err := sgauth.NewHTTPClient(ctx, createSettings(args))
if err != nil {
	// Call REST Google API here
}
client := &client.Client{
		HTTP:        http,
		BaseURL:     "YOUR_PROTORPC_BASE_URL",
		UserAgent:   "protorpc/0.1",
}
```

