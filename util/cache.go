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
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/oauth2"
)

const CacheFileName = ".oauth2l"

var CacheLocation string = filepath.Join(GuessUnixHomeDir(), CacheFileName)

// The key struct that used to identify an auth token fetch operation.
type CacheKey struct {
	// The JSON credentials content downloaded from Google Cloud Console.
	CredentialsJSON string
	// If specified, use OAuth. Otherwise, JWT.
	Scope string
	// The audience field for JWT auth and UAT
	Audience string
	// The email used for SSO and domain-wide delegation.
	Email string
	// The Google API key
	APIKey string
	// The QuotaProject field for STS
	QuotaProject string
	// If specified, performs STS exchange on top of base OAuth
	Sts bool
	// Exchange User access token for Service Account access token.
	ServiceAccount string
}

func LookupCache(settings *Settings) (*oauth2.Token, error) {
	if CacheLocation == "" {
		return nil, nil
	}
	var cache, err = loadCache()
	if err != nil {
		return nil, err
	}
	key, err := json.Marshal(createKey(settings))
	if err != nil {
		return nil, err
	}
	val := cache[string(key)]
	return UnmarshalWithExtras(val)
}

func InsertCache(settings *Settings, token *oauth2.Token) error {
	if CacheLocation == "" {
		return nil
	}
	var cache, err = loadCache()
	if err != nil {
		return err
	}
	val, err := MarshalWithExtras(token, "")
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

func createKey(settings *Settings) CacheKey {
	// Removing redirect_uri from credentials file. This allows for dynamic
	// localhost ports created during 3LO loopback.
	var credentialsJSON string = settings.CredentialsJSON
	re := regexp.MustCompile("\"redirect_uris\":([[:graph:]\\s]*?)\\]")
	match := re.FindString(credentialsJSON)
	credentialsJSON = strings.Replace(credentialsJSON, match, "\"redirect_uris\":[]", 1)

	return CacheKey{
		CredentialsJSON: credentialsJSON,
		Scope:           settings.Scope,
		Audience:        settings.Audience,
		Email:           settings.Email,
		APIKey:          settings.APIKey,
		QuotaProject:    settings.QuotaProject,
		Sts:             settings.Sts,
		ServiceAccount:  settings.ServiceAccount,
	}
}

func GuessUnixHomeDir() string {
	// Prefer $HOME over user.Current due to glibc bug: golang.org/issue/13470
	if v := os.Getenv("HOME"); v != "" {
		return v
	}
	// Else, fall back to user.Current:
	if u, err := user.Current(); err == nil {
		return u.HomeDir
	}
	return ""
}

// Marshals the given oauth2.Token into a JSON bytearray and include Extra
// fields that normally would be omitted with default marshalling.
func MarshalWithExtras(token *oauth2.Token, indent string) ([]byte, error) {
	data, err := json.Marshal(token)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	err = json.Unmarshal(data, &m)
	if err != nil {
		return nil, err
	}
	if token.Extra("issued_token_type") != nil {
		m["issued_token_type"] = token.Extra("issued_token_type").(string)
	}
	if token.Extra("id_token") != nil {
		m["id_token"] = token.Extra("id_token").(string)
	}
	if token.Extra("scope") != nil {
		m["scope"] = token.Extra("scope").(string)
	}
	return json.MarshalIndent(m, "", indent)
}

// Unmarshals the given JSON bytearray into oauth2.Token and include Extra
// fields that normally would be omitted with default unmarshalling.
func UnmarshalWithExtras(data []byte) (*oauth2.Token, error) {
	var extra map[string]interface{}
	err := json.Unmarshal(data, &extra)
	if err != nil {
		return nil, err
	}
	var token oauth2.Token
	err = json.Unmarshal(data, &token)
	if err != nil {
		return nil, err
	}
	return token.WithExtra(extra), nil
}
