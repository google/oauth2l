//
// Copyright 2015 Google Inc.
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

package oauth2util

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

var dummyPrivateKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAx4fm7dngEmOULNmAs1IGZ9Apfzh+BkaQ1dzkmbUgpcoghucE
DZRnAGd2aPyB6skGMXUytWQvNYav0WTR00wFtX1ohWTfv68HGXJ8QXCpyoSKSSFY
fuP9X36wBSkSX9J5DVgiuzD5VBdzUISSmapjKm+DcbRALjz6OUIPEWi1Tjl6p5RK
1w41qdbmt7E5/kGhKLDuT7+M83g4VWhgIvaAXtnhklDAggilPPa8ZJ1IFe31lNlr
k4DRk38nc6sEutdf3RL7QoH7FBusI7uXV03DC6dwN1kP4GE7bjJhcRb/7jYt7CQ9
/E9Exz3c0yAp0yrTg0Fwh+qxfH9dKwN52S7SBwIDAQABAoIBAQCaCs26K07WY5Jt
3a2Cw3y2gPrIgTCqX6hJs7O5ByEhXZ8nBwsWANBUe4vrGaajQHdLj5OKfsIDrOvn
2NI1MqflqeAbu/kR32q3tq8/Rl+PPiwUsW3E6Pcf1orGMSNCXxeducF2iySySzh3
nSIhCG5uwJDWI7a4+9KiieFgK1pt/Iv30q1SQS8IEntTfXYwANQrfKUVMmVF9aIK
6/WZE2yd5+q3wVVIJ6jsmTzoDCX6QQkkJICIYwCkglmVy5AeTckOVwcXL0jqw5Kf
5/soZJQwLEyBoQq7Kbpa26QHq+CJONetPP8Ssy8MJJXBT+u/bSseMb3Zsr5cr43e
DJOhwsThAoGBAPY6rPKl2NT/K7XfRCGm1sbWjUQyDShscwuWJ5+kD0yudnT/ZEJ1
M3+KS/iOOAoHDdEDi9crRvMl0UfNa8MAcDKHflzxg2jg/QI+fTBjPP5GOX0lkZ9g
z6VePoVoQw2gpPFVNPPTxKfk27tEzbaffvOLGBEih0Kb7HTINkW8rIlzAoGBAM9y
1yr+jvfS1cGFtNU+Gotoihw2eMKtIqR03Yn3n0PK1nVCDKqwdUqCypz4+ml6cxRK
J8+Pfdh7D+ZJd4LEG6Y4QRDLuv5OA700tUoSHxMSNn3q9As4+T3MUyYxWKvTeu3U
f2NWP9ePU0lV8ttk7YlpVRaPQmc1qwooBA/z/8AdAoGAW9x0HWqmRICWTBnpjyxx
QGlW9rQ9mHEtUotIaRSJ6K/F3cxSGUEkX1a3FRnp6kPLcckC6NlqdNgNBd6rb2rA
cPl/uSkZP42Als+9YMoFPU/xrrDPbUhu72EDrj3Bllnyb168jKLa4VBOccUvggxr
Dm08I1hgYgdN5huzs7y6GeUCgYEAj+AZJSOJ6o1aXS6rfV3mMRve9bQ9yt8jcKXw
5HhOCEmMtaSKfnOF1Ziih34Sxsb7O2428DiX0mV/YHtBnPsAJidL0SdLWIapBzeg
KHArByIRkwE6IvJvwpGMdaex1PIGhx5i/3VZL9qiq/ElT05PhIb+UXgoWMabCp84
OgxDK20CgYAeaFo8BdQ7FmVX2+EEejF+8xSge6WVLtkaon8bqcn6P0O8lLypoOhd
mJAYH8WU+UAy9pecUnDZj14LAGNVmYcse8HFX71MoshnvCTFEPVo4rZxIAGwMpeJ
5jgQ3slYLpqrGlcbLgUXBUgzEO684Wk/UV9DFPlHALVqCfXQ9dpJPg==
-----END RSA PRIVATE KEY-----`)

func newClientSecretJson(url string) []byte {
	s := map[string]interface{}{
		"installed": map[string]interface{}{
			"auth_provider_x509_cert_url": url + "/certs",
			"auth_uri":                    url + "/auth",
			"client_id":                   "this-is-a-client-id",
			"client_secret":               "this-is-a-client-secret",
			"project_id":                  "this-is-a-project-id",
			"redirect_uris": []string{
				"urn:ietf:wg:oauth:2.0:oob",
				"http://localhost",
			},
			"token_uri": url + "/token",
		},
	}
	bytes, _ := json.Marshal(s)
	return bytes
}

func newServiceAccountJson(url string) []byte {
	s := map[string]interface{}{
		"auth_provider_x509_cert_url": url + "/certs",
		"auth_uri":                    url + "/auth",
		"client_email": "someone@this-is-a-project-id.iam.gserviceaccount.com",
		"client_id":                   "this-is-a-client-id",
		"client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/someone%40this-is-a-project-id.iam.gserviceaccount.com",
		"private_key":               string(dummyPrivateKey),
		"private_key_id": "0000000000000000000000000000000000000000",
		"project_id":                  "this-is-a-project-id",
		"token_uri": url + "/token",
		"type": "service_account",
	}
	bytes, _ := json.Marshal(s)
	return bytes
}

func newTokenJson(refreshToken string) []byte {
	t := oauth2.Token{
		AccessToken:  "ya29.qwertyuiop",
		TokenType:    "Bearer",
		RefreshToken: refreshToken,
		Expiry:       time.Unix(int64(time.Now().Unix())+3600, 0),
	}
	bytes, _ := json.Marshal(t)
	return bytes
}

func TestClientSecret(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("authenticate client request URL = %v; want %v", r.URL, "/token")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(newTokenJson("1/asdfghjkl"))
	}))
	defer server.Close()

	handlerCalled := false
	handler := func(url string) (string, error) {
		handlerCalled = true
		return "abc", nil
	}

	key := newClientSecretJson(server.URL)
	ts, err := NewTokenSource(context.Background(), key, handler, "scope1", "scope2")
	if err != nil {
		t.Errorf("Failed in NewTokenSource: %v", err)
	}

	if !handlerCalled {
		t.Errorf("Handler not called.")
	}

	token, err := ts.Token()
	if err != nil {
		t.Errorf("Failed to call Token: %v", err)
	}

	if got, want := token.AccessToken, "ya29.qwertyuiop"; got != want {
		t.Errorf("Access token = %v; want %v", got, want)
	}

	if got, want := token.RefreshToken, "1/asdfghjkl"; got != want {
		t.Errorf("Refresh token = %v; want %v", got, want)
	}
}

func TestServiceAccount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/token" {
			t.Errorf("authenticate client request URL = %v; want %v", r.URL, "/token")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(newTokenJson(""))
	}))
	defer server.Close()

	key := newServiceAccountJson(server.URL)
	ts, err := NewTokenSource(context.Background(), key, nil, "scope1", "scope2")
	if err != nil {
		t.Errorf("Failed in NewTokenSource: %v", err)
	}

	token, err := ts.Token()
	if err != nil {
		t.Errorf("Failed to call Token: %v", err)
	}

	if got, want := token.AccessToken, "ya29.qwertyuiop"; got != want {
		t.Errorf("Access token = %v; want %v", got, want)
	}

	if token.RefreshToken != "" {
		t.Errorf("Refresh token = %v which is not empty.", token.RefreshToken)
	}
}
