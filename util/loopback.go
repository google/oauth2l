//
// Copyright 2020 Google Inc.
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
//
// loopback implements an authorization code localhost server that
// handles 3LO loopback flows. (see AuthorizationCodeServer interface)
package util

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Loopback server endpoints
const (
	SERVER_STATUS_ENDPOINT_URL   = "/status/get"
	SERVER_LOOPBACK_ENDPOINT_URL = "/"
)

type AuthorizationCodeRequestStatus int

// Phases of the authorization code
const (
	// Waiting for authorization code
	// (waiting for authorization code request to start,
	//	or for authorization code request to complete)
	WAITING AuthorizationCodeRequestStatus = iota
	// Authorization code successfully granted.
	GRANTED
	// Failed to grant authorization code
	FAILED
)

// AuthorizationCodeServer represents a localhost server
// that handles the Loopback 3LO authorization
type AuthorizationCodeServer interface {
	// Starts listening and serving on the provided address.
	// If no port is specified in the address, an available port is assigned.
	//
	// Input address: represents a localhost address. Its format is http://localhost[:port]
	//
	// Returns serverAddress: is the address of the listener. Its format is http://localhost[:port]
	// Returns err: if server fails to listen or serve.
	ListenAndServe(address string) (serverAddress string, err error)

	// Stops listening and serving.
	Close()

	// IsListeningAndServing determines if the server is listening and serving.
	//
	// Returns isLisAndServ: true if this is listening and serving, false otherwise.
	IsListeningAndServing() (isLisAndServ bool)

	// WaitForListeningAndServing waits until the server is listening and serving,
	// or until a timeout occurs.
	//
	// Input maxWaitTime: is the maximum time to wait for the server to start
	// listening and serving.
	//
	// Returns isLisAndServ: true if the server is listening and serving.
	// false if the server fails to listen and server before
	// Returns err: if isLisAndServ is false.
	WaitForListeningAndServing(maxWaitTime time.Duration) (isLisAndServ bool, err error)

	// Returns the AuthorizationCode.
	//
	// Returns authCode: represents the authorization code.
	// if not yet granted its value is an empty string.
	// Returns err: is not nil if the code has not been granted.
	GetAuthenticationCode() (authCode AuthorizationCode, err error)

	// WaitForConsentPageToReturnControl waits until the consent page returns control.
	//
	// Returns err: if the consent page fails to return control
	// within the maxWaitTime.
	WaitForConsentPageToReturnControl() (err error)
}

// AuthorizationCode represents the authorization code
type AuthorizationCode struct {
	Code  string
	State string
}

// AuthorizationCodeStatus represents the state
// of the authorization code
type AuthorizationCodeStatus struct {
	Status  AuthorizationCodeRequestStatus
	Details string
}

// ConsentPageSettings is a 3-legged-OAuth helper that
// contains the settings for the interaction with the consent page
type ConsentPageSettings struct {
	// DisableAutoOpenConsentPage controls the feature to automatically
	// open the browser to vist the consent page
	DisableAutoOpenConsentPage bool
	// InteractionTimeout is the maximum time to wait for the user
	// to interact with the consent page
	InteractionTimeout time.Duration
}

// AuthorizationCodeLocalhost implements AuthorizationCodeServer.
// See interface for description
type AuthorizationCodeLocalhost struct {
	AuthCodeReqStatus   AuthorizationCodeStatus
	ConsentPageSettings ConsentPageSettings
	addr                string
	authCode            AuthorizationCode
	server              *http.Server
}

func (lh *AuthorizationCodeLocalhost) ListenAndServe(address string) (serverAddress string, err error) {
	listener, serverAddress, err := GetListener(address)
	if err != nil {
		return "", fmt.Errorf("Unable to Listen: %v", err)
	}

	lh.addr = serverAddress

	// Setup local host in given address
	mux := http.NewServeMux()
	lh.server = &http.Server{Addr: strings.Replace(lh.addr, "http://", "", 1), Handler: mux}
	mux.HandleFunc(SERVER_LOOPBACK_ENDPOINT_URL, lh.redirectUriHandler)
	mux.HandleFunc(SERVER_STATUS_ENDPOINT_URL, lh.statusGetHandler)

	go func() {
		// Start Listed and Serve
		if err := lh.server.Serve(*listener); err != nil && err != http.ErrServerClosed {
			fmt.Printf("Could not listen on address: %v. Error: %v\n", lh.addr, err)
		}
	}()

	return serverAddress, nil
}

func (lh *AuthorizationCodeLocalhost) Close() {
	if lh.server == nil {
		return
	}

	// Stoping server
	lh.server.Close()
	lh.server = nil
	lh.addr = ""
}

func (lh *AuthorizationCodeLocalhost) IsListeningAndServing() (isLisAndServ bool) {
	if lh.server == nil {
		return false
	}

	_, err := http.Get(lh.addr + "/status/get")
	return err == nil
}

func (lh *AuthorizationCodeLocalhost) WaitForListeningAndServing(maxWaitTime time.Duration) (isLisAndServ bool, err error) {
	if lh.server == nil {
		return false, fmt.Errorf("Server has not been set.")
	}

	timeout := false
	timer := time.AfterFunc(maxWaitTime, func() {
		timeout = true
	})

	defer timer.Stop()

	for !timeout && !lh.IsListeningAndServing() {
		// Loop until:
		// - maxWaitTime is reached
		// - server is listening and serving
	}

	if !lh.IsListeningAndServing() {
		return false, fmt.Errorf("Timed out.")
	}
	return true, nil
}

func (lh *AuthorizationCodeLocalhost) GetAuthenticationCode() (authCode AuthorizationCode, err error) {
	if lh.AuthCodeReqStatus.Status != GRANTED {
		return lh.authCode, fmt.Errorf(lh.AuthCodeReqStatus.Details)
	}
	return lh.authCode, nil
}

func (lh *AuthorizationCodeLocalhost) WaitForConsentPageToReturnControl() (err error) {
	if lh.server == nil {
		return fmt.Errorf("Server has not been set.")
	}

	timeout := false
	timer := time.AfterFunc(lh.ConsentPageSettings.InteractionTimeout, func() {
		timeout = true
	})

	defer timer.Stop()

	for !timeout && lh.AuthCodeReqStatus.Status == WAITING {
		// Loop until:
		// - maxWaitTime is reached
		// - authorization code status is not waiting
	}

	if lh.AuthCodeReqStatus.Status == WAITING {
		return fmt.Errorf("Timed out.")
	}
	return nil
}

// redirectUriHandler handles the redirect logic when aquiring the authorization code.
func (lh *AuthorizationCodeLocalhost) redirectUriHandler(w http.ResponseWriter, r *http.Request) {
	const (
		closeTab string = ". Please close this tab."
	)

	rq := r.URL.RawQuery
	urlValues, err := url.ParseQuery(rq)
	if err != nil {
		err := fmt.Sprintf("Unable to parse query: %v", err)

		lh.AuthCodeReqStatus = AuthorizationCodeStatus{Status: FAILED, Details: err}
		lh.authCode = AuthorizationCode{}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(lh.AuthCodeReqStatus.Details + closeTab))
		return
	}

	urlError := urlValues.Get("error")
	// Authentication Code Error from consent page
	if urlError != "" {
		err := fmt.Sprintf("An error occurred when getting authorization code: %s", urlError)
		lh.AuthCodeReqStatus = AuthorizationCodeStatus{Status: FAILED, Details: err}
		lh.authCode = AuthorizationCode{}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(lh.AuthCodeReqStatus.Details + closeTab))
		return
	}

	urlCode := urlValues.Get("code")
	urlState := urlValues.Get("state")
	// No Code, Status, or Error is treated as unknown error
	if urlCode == "" && urlState == "" {
		err := "Unknown error when getting authorization code"
		lh.AuthCodeReqStatus = AuthorizationCodeStatus{Status: FAILED, Details: err}

		lh.authCode = AuthorizationCode{}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(lh.AuthCodeReqStatus.Details + closeTab))
		return
	}

	//  Authorization code returned
	if urlCode != "" && urlState != "" {
		lh.authCode = AuthorizationCode{
			Code:  urlCode,
			State: urlState,
		}

		lh.AuthCodeReqStatus = AuthorizationCodeStatus{
			Status: GRANTED, Details: "Authorization code granted"}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(lh.AuthCodeReqStatus.Details + closeTab))
		return
	}

	err = fmt.Errorf("Authorization code missing code or state.")
	lh.AuthCodeReqStatus = AuthorizationCodeStatus{Status: FAILED, Details: err.Error()}

	lh.authCode = AuthorizationCode{}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(lh.AuthCodeReqStatus.Details + closeTab))
	return
}

// statusGetHandler handles request to get the localhost status
func (lh *AuthorizationCodeLocalhost) statusGetHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Status OK"))
	return
}

// GetListener gets a listener on the port specified in the address.
// If no port is specified in the address, an available port is assigned.
//
// Input address: represents a localhost address. Its format is http://localhost[:port]
//
// Returns listener
// Returns serverAddress: is the address of the listener. Its format is http://localhost[:port]
// Returns err: if not nil an error occurred when creating the listener.
func GetListener(address string) (listener *net.Listener, serverAddress string, err error) {
	var l net.Listener = nil

	re := regexp.MustCompile("localhost:\\d+")
	match := re.FindString(address)

	if match == "" { // Case: No given port provided for localhost
		// Creating a listener on the next available port
		l, err = net.Listen("tcp", "localhost:0")
	} else { // Case: Port provided for localhost
		// Creating a listener on the provided port
		l, err = net.Listen("tcp", match)
	}

	if err != nil {
		return nil, "", fmt.Errorf("Unable to open port: %v", err)
	}

	tcpPort := (l).Addr().(*net.TCPAddr).Port
	// Updating redirect uri to reflect port to use.
	localhostAddr := "http://localhost:" + strconv.Itoa(tcpPort)
	return &l, localhostAddr, nil
}
