//
// Copyright 2018 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package credentials

import (
	"crypto/rsa"
	"fmt"
	"time"

	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/google/oauth2l/sgauth/internal"
	"golang.org/x/oauth2/jws"
)

// JWTConfigFromJSON uses a Google Developers service account JSON key file to read
// the credentials that authorize and authenticate the requests.
// Create a service account on "Credentials" for your project at
// https://console.developers.google.com to download a JSON key file.
func JWTConfigFromJSON(jsonKey []byte, scope ...string) (*JWTConfig, error) {
	var f File
	if err := json.Unmarshal(jsonKey, &f); err != nil {
		return nil, err
	}
	if f.Type != ServiceAccountKey {
		return nil, fmt.Errorf("google: read JWT from JSON credentials: 'type' field is %q (expected %q)", f.Type, ServiceAccountKey)
	}
	scope = append([]string(nil), scope...) // copy
	return JWTConfigFromFile(&f, scope), nil
}

// JWTAccessTokenSourceFromJSON uses a Google Developers service account JSON
// key file to read the credentials that authorize and authenticate the
// requests, and returns a TokenSource that does not use any OAuth2 flow but
// instead creates a JWT and sends that as the access token.
// The audience is typically a URL that specifies the scope of the credentials.
//
// Note that this is not a standard OAuth flow, but rather an
// optimization supported by a few Google services.
// Unless you know otherwise, you should use JWTConfigFromJSON instead.
func JWTAccessTokenSourceFromJSON(jsonKey []byte, audience string) (internal.TokenSource, error) {
	cfg, err := JWTConfigFromJSON(jsonKey)
	if err != nil {
		return nil, fmt.Errorf("google: could not parse JSON key: %v", err)
	}
	pk, err := parseKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("google: could not parse key: %v", err)
	}
	ts := &jwtAccessTokenSource{
		email:    cfg.Email,
		audience: audience,
		pk:       pk,
		pkID:     cfg.PrivateKeyID,
	}
	tok, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return internal.ReuseTokenSource(tok, ts), nil
}

type jwtAccessTokenSource struct {
	email, audience string
	pk              *rsa.PrivateKey
	pkID            string
}

func (ts *jwtAccessTokenSource) Token() (*internal.Token, error) {
	iat := time.Now()
	exp := iat.Add(time.Hour)
	cs := &jws.ClaimSet{
		Iss: ts.email,
		Sub: ts.email,
		Aud: ts.audience,
		Iat: iat.Unix(),
		Exp: exp.Unix(),
	}
	hdr := &jws.Header{
		Algorithm: "RS256",
		Typ:       "JWT",
		KeyID:     string(ts.pkID),
	}
	msg, err := jws.Encode(hdr, cs, ts.pk)
	if err != nil {
		return nil, fmt.Errorf("google: could not encode JWT: %v", err)
	}
	return &internal.Token{AccessToken: msg, TokenType: "Bearer", Expiry: exp}, nil
}

// ParseKey converts the binary contents of a private key file
// to an *rsa.PrivateKey. It detects whether the private key is in a
// PEM container or not. If so, it extracts the the private key
// from PEM container before conversion. It only supports PEM
// containers with no passphrase.
func parseKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("private key should be a PEM or plain PKSC1 or PKCS8; parse error: %v", err)
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is invalid")
	}
	return parsed, nil
}
