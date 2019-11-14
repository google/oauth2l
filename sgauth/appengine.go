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
package sgauth

import (
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/oauth2l/sgauth/internal"
	"golang.org/x/net/context"
)

// appengineFlex is set at init time by appengineflex_hook.go. If true, we are on App Engine Flex.
var appengineFlex bool

// Set at init time by appengine_hook.go. If nil, we're not on App Engine.
var appengineTokenFunc func(c context.Context, scopes ...string) (token string, expiry time.Time, err error)

// Set at init time by appengine_hook.go. If nil, we're not on App Engine.
var appengineAppIDFunc func(c context.Context) string

// AppEngineTokenSource returns a token source that fetches tokens
// issued to the current App Engine application's service account.
// If you are implementing a 3-legged OAuth 2.0 flow on App Engine
// that involves user accounts, see oauth2.Config instead.
//
// The provided context must have come from appengine.NewContext.
func AppEngineTokenSource(ctx context.Context, scope ...string) internal.TokenSource {
	if appengineTokenFunc == nil {
		panic("google: AppEngineTokenSource can only be used on App Engine.")
	}
	scopes := append([]string{}, scope...)
	sort.Strings(scopes)
	return &appEngineTokenSource{
		ctx:    ctx,
		scopes: scopes,
		key:    strings.Join(scopes, " "),
	}
}

// aeTokens helps the fetched tokens to be reused until their expiration.
var (
	aeTokensMu sync.Mutex
	aeTokens   = make(map[string]*tokenLock) // key is space-separated scopes
)

type tokenLock struct {
	mu sync.Mutex // guards t; held while fetching or updating t
	t  *internal.Token
}

type appEngineTokenSource struct {
	ctx    context.Context
	scopes []string
	key    string // to aeTokens map; space-separated scopes
}

func (ts *appEngineTokenSource) Token() (*internal.Token, error) {
	if appengineTokenFunc == nil {
		panic("google: AppEngineTokenSource can only be used on App Engine.")
	}

	aeTokensMu.Lock()
	tok, ok := aeTokens[ts.key]
	if !ok {
		tok = &tokenLock{}
		aeTokens[ts.key] = tok
	}
	aeTokensMu.Unlock()

	tok.mu.Lock()
	defer tok.mu.Unlock()
	if tok.t.Valid() {
		return tok.t, nil
	}
	access, exp, err := appengineTokenFunc(ts.ctx, ts.scopes...)
	if err != nil {
		return nil, err
	}
	tok.t = &internal.Token{
		AccessToken: access,
		Expiry:      exp,
	}
	return tok.t, nil
}
