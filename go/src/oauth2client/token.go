package oauth2client

import (
	"time"
)

// Definition for OAuth2 token type.
// Referenced from https://godoc.org/golang.org/x/oauth2#Token
type Token struct {
	// AccessToken is the token that authorizes and authenticates
	// the requests.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`

	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`

	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`
	// contains filtered or unexported fields

	// ExpiresIn is the optional expiration time in seconds.
	ExpiresIn *int `json:"expires_in,omitempty"`
}
