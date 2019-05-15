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
package util

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"github.com/google/oauth2l/sgauth"
)

const CacheFileName = ".oauth2l"

var CacheLocation string = filepath.Join(sgauth.GuessUnixHomeDir(), CacheFileName)

// The key struct that used to identify an auth token fetch operation.
type CacheKey struct {
	// The JSON credentials content downloaded from Google Cloud Console.
	CredentialsJSON string
	// If specified, use OAuth. Otherwise, JWT.
	Scope string
	// The audience field for JWT auth
	Audience string
	// The Google API key
	APIKey string
}

func LookupCache(settings *sgauth.Settings) (*sgauth.Token, error) {
	if CacheLocation == "" {
		return nil, nil
	}
	var token sgauth.Token
	var cache, err = loadCache()
	if err != nil {
		return nil, err
	}
	key, err := json.Marshal(createKey(settings))
	if err != nil {
		return nil, err
	}
	val := cache[string(key)]
	err = json.Unmarshal(val, &token)
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func InsertCache(settings *sgauth.Settings, token *sgauth.Token) error {
	if CacheLocation == "" {
		return nil
	}
	var cache, err = loadCache()
	if err != nil {
		return err
	}
	val, err := json.Marshal(*token)
	if err != nil {
		return err
	}
	key, err := json.Marshal(createKey(settings))
	if err != nil {
		return err
	}
	cache[string(key)] = val
	data, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(CacheLocation, data, 0666)
}

func ClearCache() error {
	if CacheLocation == "" {
		return nil
	}
	if _, err := os.Stat(CacheLocation); os.IsNotExist(err) {
		// Noop if file does not exist.
		return nil
	}
	return os.Remove(CacheLocation)
}

func loadCache() (map[string][]byte, error) {
	if _, err := os.Stat(CacheLocation); os.IsNotExist(err) {
		// Create the cache file if not existing.
		f, err := os.OpenFile(CacheLocation, os.O_RDONLY|os.O_CREATE, 0666)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
		f.Close()
	}
	data, err := ioutil.ReadFile(CacheLocation)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}
	m := make(map[string][]byte)
	if len(data) > 0 {
		err = json.Unmarshal(data, &m)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
	}
	return m, nil
}

func createKey(settings *sgauth.Settings) CacheKey {
	return CacheKey{
		CredentialsJSON: settings.CredentialsJSON,
		Scope:           settings.Scope,
		Audience:        settings.Audience,
		APIKey:          settings.APIKey,
	}
}
