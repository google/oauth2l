//
// Copyright 2019 Google Inc.
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
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/google/oauth2l/util"
)

// Use this flag to update golden files with test outputs from current run.
var update = flag.Bool("update", false, "update golden files")

// The name of the CLI to test.
const binaryName = "oauth2l"

// The full path of the CLI to test.
var binaryPath string

type testFile struct {
	t    *testing.T
	name string
	dir  string
}

func newFixture(t *testing.T, name string) *testFile {
	return &testFile{t: t, name: name, dir: "fixtures"}
}

func newGoldenFile(t *testing.T, name string) *testFile {
	return &testFile{t: t, name: name, dir: "golden"}
}

func (tf *testFile) path() string {
	tf.t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		tf.t.Fatal("problems recovering caller information")
	}

	return filepath.Join(filepath.Dir(filename), tf.dir, tf.name)
}

func (tf *testFile) write(content string) {
	tf.t.Helper()
	err := ioutil.WriteFile(tf.path(), []byte(content), 0644)
	if err != nil {
		tf.t.Fatalf("could not write %s: %v", tf.name, err)
	}
}

func (tf *testFile) asFile() *os.File {
	tf.t.Helper()
	file, err := os.Open(tf.path())
	if err != nil {
		tf.t.Fatalf("could not open %s: %v", tf.name, err)
	}
	return file
}

func (tf *testFile) load() string {
	tf.t.Helper()

	content, err := ioutil.ReadFile(tf.path())
	if err != nil {
		tf.t.Fatalf("could not read file %s: %v", tf.name, err)
	}

	return string(content)
}

// saveAs saves the currect instance into another file in the same directory.
// The current instance is not substituted by the newly create one.
//
// input filename: is the new filename.
func (tf *testFile) saveAs(filename string) {
	content := tf.load()
	temp := tf.name
	tf.name = filename
	tf.write(content)
	tf.name = temp
}

type testCase struct {
	name    string
	args    []string
	golden  string
	wantErr bool
}

// Runs basic test cases.
func runTestScenarios(t *testing.T, tests []testCase) {
	runTestScenariosWithInput(t, tests, nil)
}

// Runs test cases where stdin input is needed.
func runTestScenariosWithInput(t *testing.T, tests []testCase, input *os.File) {
	runTestScenariosWithInputAndProcessedOutput(t, tests, input, nil)
}

// Used for processing test output before comparing to golden files.
type processOutput func(string) string

// Used for additional logic before executing oauth2l's command.
type preCommandLogic func(tc *testCase) error

// Used for additional logic after executing oauth2l's command.
type postCommandLogic func()

// Runs tests where extra logic needs to be added before/after the command execution.
//
// input processOutput: processes test output before comparing to golden files
// input preCmdLogic: additional logic excuted once per test case before command excution. It allows for test argument manipulation.
// input postCmdLogic: additional logic excuted once per test case after command excution. It allows for cleanup.
func runTestScenariosWithAdvancedLogic(t *testing.T, tests []testCase, input *os.File, processOutput processOutput,
	preCmdLogic preCommandLogic, postCmdLogic postCommandLogic) {
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Processing logic before exec. Command
			if preCmdLogic != nil {
				if err := preCmdLogic(&tc); err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
			}

			cmd := exec.Command(binaryPath, tc.args...)
			if input != nil {
				cmd.Stdin = input
			}

			// exec.Command and gathering output
			output, err := cmd.CombinedOutput()

			// Processing logic after exec. Command
			if postCmdLogic != nil {
				postCmdLogic()
			}
			if (err != nil) != tc.wantErr {
				t.Fatalf("%s\nexpected (err != nil) to be %v, but got %v. err: %v", output, tc.wantErr, err != nil, err)
			}
			actual := string(output)

			if processOutput != nil {
				actual = processOutput(actual)
			}

			golden := newGoldenFile(t, tc.golden)

			if *update {
				golden.write(actual)
			}
			expected := golden.load()
			if !reflect.DeepEqual(expected, actual) {
				t.Fatalf("Expected: %v Actual: %v", expected, actual)
			}
		})
	}
}

// Runs test cases where stdin input is needed and output needs to be processed before comparing to golden files.
func runTestScenariosWithInputAndProcessedOutput(t *testing.T, tests []testCase, input *os.File, processOutput processOutput) {
	runTestScenariosWithAdvancedLogic(t, tests, input, processOutput, nil, nil)
}

// Helper for removing the randomly generated redirect uri's port from comparison.
func removeRedirectUriPort(s string) string {
	re := regexp.MustCompile("redirect_uri=.*http%3A%2F%2Flocalhost%3A\\d+")
	match := re.FindString(s)
	if match != "" {
		return strings.Replace(s, match, "redirect_uri=http%3A%2F%2Flocalhost", 1)
	}
	return s
}

// Helper for removing the randomly generated code_challenge string from comparison.
func removeCodeChallenge(s string) string {
	re := regexp.MustCompile("code_challenge=.*code_challenge_method")
	match := re.FindString(s)
	if match == "" {
		return s
	}
	return strings.Replace(s, match, "code_challenge_method", 1)
}

// Test base-case scenarios
func TestCLI(t *testing.T) {
	tests := []testCase{
		{
			"no command",
			[]string{},
			"no-command.golden",
			false,
		},
		{
			"fetch; no scope",
			[]string{"fetch"},
			"no-scope.golden",
			false,
		},
		{
			"fetch; jwt; no audience",
			[]string{"fetch", "--type", "jwt"},
			"no-scope-or-audience.golden",
			false,
		},
		{
			"fetch; sso; no email",
			[]string{"fetch", "--type", "sso"},
			"no-email.golden",
			false,
		},
		{
			"fetch; sso; no scope",
			[]string{"fetch", "--type", "sso", "--email", "example@example.com"},
			"no-scope-sso.golden",
			false,
		},
		{
			"header; no scope",
			[]string{"header"},
			"no-scope.golden",
			false,
		},
		{
			"curl; no scope",
			[]string{"curl", "--url", "https://test.com"},
			"no-scope.golden",
			false,
		},
		{
			"curl; no url",
			[]string{"curl"},
			"no-url.golden",
			false,
		},
		{
			"info; invalid token",
			[]string{"info", "--token", "invalid-token"},
			"info-invalid-token.golden",
			false,
		},
		{
			"test; invalid token",
			[]string{"test", "--token", "invalid-token"},
			"test-invalid-token.golden",
			true,
		},
		{
			"reset",
			[]string{"reset"},
			"empty.golden",
			false,
		},
	}
	runTestScenarios(t, tests)
}

// TODO: Remove this flow when the 3LO flow is deprecated. A replicated set of test is now part of Test3LOLoopbackFlow.
// tests in Test3LOLoopbackFlow have been updated to account for new outputs.
// Test OAuth 3LO flow with fake client secrets. Fake verification code is injected to stdin to advance the flow.
func Test3LOFlow(t *testing.T) {
	tests := []testCase{
		{
			"fetch; 3lo",
			[]string{"fetch", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets.json", "--cache", ""},
			"fetch-3lo.golden",
			false,
		},
		{
			"fetch; 3lo; old interface",
			[]string{"fetch", "--json", "integration/fixtures/fake-client-secrets.json", "--cache", "", "pubsub"},
			"fetch-3lo.golden",
			false,
		},
		{
			"fetch; 3lo; openid scopes",
			[]string{"fetch", "--scope", "openid,profile,email", "--credentials", "integration/fixtures/fake-client-secrets.json", "--cache", ""},
			"fetch-3lo-openid.golden",
			false,
		},
		{
			"fetch; 3lo; userinfo scopes",
			[]string{"fetch", "--scope", "userinfo.profile,userinfo.email", "--credentials", "integration/fixtures/fake-client-secrets.json", "--cache", ""},
			"fetch-3lo-userinfo.golden",
			false,
		},
		{
			"header; 3lo",
			[]string{"header", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets.json", "--cache", ""},
			"header-3lo.golden",
			false,
		},
		{
			"fetch; 3lo; refresh token output format",
			[]string{"fetch", "--output_format", "refresh_token", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets.json", "--cache", ""},
			"fetch-3lo-refresh-token.golden",
			false,
		},
		{
			"curl; 3lo",
			[]string{"curl", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets.json", "--url", "http://localhost:8080/curl"},
			"curl-3lo.golden",
			false,
		},
		{
			"fetch; 3lo cached",
			[]string{"fetch", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets.json"},
			"fetch-3lo-cached.golden",
			false,
		},
		{
			"fetch; 3lo insert expired token into cache",
			[]string{"fetch", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets-expired-token.json"},
			"fetch-3lo.golden",
			false,
		},
		{
			"fetch; 3lo cached; token expired",
			[]string{"fetch", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets-expired-token.json"},
			"fetch-3lo.golden",
			false,
		},
		{
			"fetch; 3lo cached; refresh expired token",
			[]string{"fetch", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets-expired-token.json", "--refresh"},
			"fetch-3lo-cached.golden",
			false,
		},
	}
	process3LOOutput := func(output string) string {
		return removeCodeChallenge(output)
	}
	runTestScenariosWithInputAndProcessedOutput(t, tests, newFixture(t, "fake-verification-code.fixture").asFile(), process3LOOutput)
}

// TODO: Remove Test3LOFlow once the 3LO flow is deprecated
// Test OAuth 3LO loopback flow with fake client secrets. It does not wait for consent page interaction.
// Instead a post request with the code and state is sent to the loopback server to advance the flow.
func Test3LOLoopbackFlow(t *testing.T) {

	const (
		// NOTE: Update all consent page settings accordingly if one is changed.
		CONSENT_PAGE_TIMEOUT       = "30"
		CONSENT_PAGE_TIMEOUT_UNITS = "seconds"
		CONSENT_PAGE_DURATION      = time.Duration(30 * time.Second)
	)

	tests := []testCase{
		{
			"fetch; 3lo loopback",
			[]string{"fetch", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets-3lo-loopback.json", "--cache", "",
				"--disableAutoOpenConsentPage",
				"--consentPageInteractionTimeout", CONSENT_PAGE_TIMEOUT, "--consentPageInteractionTimeoutUnits", CONSENT_PAGE_TIMEOUT_UNITS},
			"fetch-3lo-loopback.golden",
			false,
		},
		{
			"fetch; 3lo loopback; old interface",
			[]string{"fetch", "--json", "integration/fixtures/fake-client-secrets-3lo-loopback.json", "--cache", "", "pubsub",
				"--disableAutoOpenConsentPage",
				"--consentPageInteractionTimeout", CONSENT_PAGE_TIMEOUT, "--consentPageInteractionTimeoutUnits", CONSENT_PAGE_TIMEOUT_UNITS},
			"fetch-3lo-loopback.golden",
			false,
		},
		{
			"fetch; 3lo loopback; userinfo scopes",
			[]string{"fetch", "--scope", "userinfo.profile,userinfo.email", "--credentials", "integration/fixtures/fake-client-secrets-3lo-loopback.json", "--cache", "",
				"--consentPageInteractionTimeout", CONSENT_PAGE_TIMEOUT, "--consentPageInteractionTimeoutUnits", CONSENT_PAGE_TIMEOUT_UNITS,
				"--disableAutoOpenConsentPage"},
			"fetch-3lo-loopback-userinfo.golden",
			false,
		},
		{
			"header; 3lo loopback",
			[]string{"header", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets-3lo-loopback.json", "--cache", "",
				"--consentPageInteractionTimeout", CONSENT_PAGE_TIMEOUT, "--consentPageInteractionTimeoutUnits", CONSENT_PAGE_TIMEOUT_UNITS,
				"--disableAutoOpenConsentPage"},
			"header-3lo-loopback.golden",
			false,
		},
		{
			"fetch; 3lo loopback; refresh token output format",
			[]string{"fetch", "--output_format", "refresh_token", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets-3lo-loopback.json", "--cache", "",
				"--consentPageInteractionTimeout", CONSENT_PAGE_TIMEOUT, "--consentPageInteractionTimeoutUnits", CONSENT_PAGE_TIMEOUT_UNITS,
				"--disableAutoOpenConsentPage"},
			"fetch-3lo-loopback-refresh-token.golden",
			false,
		},
		{
			"curl; 3lo loopback",
			[]string{"curl", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets-3lo-loopback.json", "--url", "http://localhost:8080/curl",
				"--consentPageInteractionTimeout", CONSENT_PAGE_TIMEOUT, "--consentPageInteractionTimeoutUnits", CONSENT_PAGE_TIMEOUT_UNITS,
				"--disableAutoOpenConsentPage"},
			"curl-3lo-loopback.golden",
			false,
		},
		{
			"fetch; 3lo loopback cached",
			[]string{"fetch", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets-3lo-loopback.json",
				"--disableAutoOpenConsentPage",
				"--consentPageInteractionTimeout", CONSENT_PAGE_TIMEOUT, "--consentPageInteractionTimeoutUnits", CONSENT_PAGE_TIMEOUT_UNITS},
			"fetch-3lo-cached.golden",
			false,
		},
		{
			"fetch; 3lo loopback insert expired token into cache",
			[]string{"fetch", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets-expired-token-3lo-loopback.json",
				"--disableAutoOpenConsentPage",
				"--consentPageInteractionTimeout", CONSENT_PAGE_TIMEOUT, "--consentPageInteractionTimeoutUnits", CONSENT_PAGE_TIMEOUT_UNITS},
			"fetch-3lo-loopback.golden",
			false,
		},
		{
			"fetch; 3lo loopback cached; token expired",
			[]string{"fetch", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets-expired-token-3lo-loopback.json",
				"--disableAutoOpenConsentPage",
				"--consentPageInteractionTimeout", CONSENT_PAGE_TIMEOUT, "--consentPageInteractionTimeoutUnits", CONSENT_PAGE_TIMEOUT_UNITS},
			"fetch-3lo-loopback.golden",
			false,
		},
		{
			"fetch; 3lo loopback cached; refresh expired token",
			[]string{"fetch", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-client-secrets-expired-token-3lo-loopback.json", "--refresh",
				"--disableAutoOpenConsentPage",
				"--consentPageInteractionTimeout", CONSENT_PAGE_TIMEOUT, "--consentPageInteractionTimeoutUnits", CONSENT_PAGE_TIMEOUT_UNITS},
			"fetch-3lo-cached.golden",
			false,
		},
	}

	type LoopbackLogicState struct {
		quitRetry   bool
		cred        *testFile
		redirectUri string
	}
	loopbackLogic := func() (func(tc *testCase) error, func()) {
		const (
			CODE_AND_STATE   = "/?state=state&code=4/gwEhAq4N7tdTj4ZStstQgaDAUpcoceoFSEPmSsoWEKVZoYSn6URLVEw"
			QUOTED_LOCALHOST = "\"http://localhost\""
			TEMP_CRED_FILE   = "temp-cred-file.json"
		)

		// Looking for available port.
		// The port is passed to the the advance logic functions.
		l, addr, err := util.GetListener("http://localhost")
		if err != nil {
			t.Fatalf("Error when getting listener: %v", err)
		}
		(*l).Close()

		var ll *LoopbackLogicState = &LoopbackLogicState{
			quitRetry:   false,
			cred:        nil,
			redirectUri: addr,
		}

		preLogic := func(tc *testCase) error {
			// Partially resetting state - keeping redirect uri.
			(*ll).quitRetry = false
			(*ll).cred = nil

			// searching for credentials filename.
			f := getCredentialsFileName(tc)
			if f == "" {
				return fmt.Errorf("Credentials file is missing. Please add to test arguments.")
			}
			changeCredentialsFileName(tc, TEMP_CRED_FILE)

			// Loading credentials file
			origFile := newFixture(t, path.Base(f))
			origFile.saveAs(TEMP_CRED_FILE)

			// Loading credentials file temp copy
			(*ll).cred = newFixture(t, TEMP_CRED_FILE)
			fileContent := (*ll).cred.load()

			// Modifiying credentials file temp copy: redirect uri
			re := regexp.MustCompile(QUOTED_LOCALHOST)
			match := re.FindString(fileContent)
			newContent := strings.Replace(fileContent, match, "\""+(*ll).redirectUri+"\"", 1)
			(*ll).cred.write(newContent)

			// Start loopback logic.
			go func() {
				timer := time.AfterFunc(CONSENT_PAGE_DURATION, func() {
					// Force ending the retry loop, so the retry logic does not loop
					// forever. postLogic may trigger an end retry logic in case the
					// exec. command finishes before the CONSET_PAGE_DURATION timeout.
					(*ll).quitRetry = true
				})
				defer timer.Stop()

				code_state_endpoint := (*ll).redirectUri + CODE_AND_STATE
				for (*ll).quitRetry != true {
					req, err := http.NewRequest("POST", code_state_endpoint, nil)
					if err == nil {
						// Sending code and state message to the localhost server handling
						// the authentication code - see loopback.go for more detials.
						res, err := http.DefaultClient.Do(req)
						if err == nil {
							res.Body.Close()
							// Ending the retry loop
							(*ll).quitRetry = true
							// Bypass sleep
							return
						}
					}
					// If unable to reach code_state_endpoint wait a second.
					time.Sleep(1 * time.Second)
				}
			}()
			return nil
		}

		postLogic := func() {
			// End loopback logic if it is still retrying:
			// In the event where exec Command exits prematurely, the loopback loop
			// should not try to POST the code and state - It would only waste resources.
			(*ll).quitRetry = true
			// Removing temp credentials file.
			os.Remove((*ll).cred.path())
			return
		}

		return preLogic, postLogic
	}

	pre, post := loopbackLogic()
	process3LOOutput := func(output string) string {
		return removeCodeChallenge(removeRedirectUriPort(output))
	}
	runTestScenariosWithAdvancedLogic(t, tests, nil, process3LOOutput, pre, post)
}

// Test OAuth 2LO Flow with fake service account.
func Test2LOFlow(t *testing.T) {
	tests := []testCase{
		{
			"fetch; 2lo",
			[]string{"fetch", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-service-account.json", "--cache", ""},
			"fetch-2lo.golden",
			false,
		},
		{
			"fetch; 2lo; old interface",
			[]string{"fetch", "--json", "integration/fixtures/fake-service-account.json", "--cache", "", "pubsub"},
			"fetch-2lo.golden",
			false,
		},
		{
			"fetch; 2lo; domain-wide delegation",
			[]string{"fetch", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-service-account.json", "--email", "testuser@google.com", "--cache", ""},
			"fetch-2lo.golden",
			false,
		},
		{
			"header; 2lo",
			[]string{"header", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-service-account.json", "--cache", ""},
			"header-2lo.golden",
			false,
		},
		{
			"curl; 2lo",
			[]string{"curl", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-service-account.json", "--url", "http://localhost:8080/curl"},
			"curl-2lo.golden",
			false,
		},
	}
	runTestScenarios(t, tests)
}

// Test JWT Flow.
func TestJWTFlow(t *testing.T) {
	tests := []testCase{
		{
			"fetch; jwt",
			[]string{"fetch", "--type", "jwt", "--audience", "https://pubsub.googleapis.com/", "--credentials", "integration/fixtures/fake-service-account.json"},
			"fetch-jwt.golden",
			false,
		},
		{
			"fetch; jwt; old interface",
			[]string{"fetch", "--jwt", "--json", "integration/fixtures/fake-service-account.json", "https://pubsub.googleapis.com/"},
			"fetch-jwt.golden",
			false,
		},
	}

	processJwtOutput := func(jwt string) string {
		//JWT is signed with a timestamp that differs in every execution, so we will strip out "exp" and "iat" fields
		encodedPayload := strings.Split(jwt, ".")[1]
		decodedPayload, _ := base64.RawStdEncoding.DecodeString(encodedPayload)
		var jsonData map[string]interface{}
		json.Unmarshal(decodedPayload, &jsonData) // nolint:errcheck
		delete(jsonData, "exp")
		delete(jsonData, "iat")
		jsonString, _ := json.Marshal(jsonData)
		return string(jsonString)
	}
	runTestScenariosWithInputAndProcessedOutput(t, tests, nil, processJwtOutput)
}

// Test SSO Flow. Uses "sh" to invoke fake ssocli to return a mock access token.
func TestSSOFlow(t *testing.T) {
	tests := []testCase{
		{
			"fetch; sso",
			[]string{"fetch", "--type", "sso", "--email", "integration/fixtures/fake-ssocli.sh", "--scope", "pubsub", "--ssocli", "sh"},
			"fetch-sso.golden",
			false,
		},
		{
			"fetch; sso; old interface",
			[]string{"fetch", "--sso", "--ssocli", "sh", "integration/fixtures/fake-ssocli.sh", "pubsub"},
			"fetch-sso.golden",
			false,
		},
	}
	runTestScenarios(t, tests)
}

// Test STS Flow.
func TestStsFlow(t *testing.T) {
	tests := []testCase{
		{
			"fetch; 2lo; sts",
			[]string{"fetch", "--scope", "pubsub", "--credentials", "integration/fixtures/fake-service-account.json", "--sts", "--audience", "http://test.com", "--quota_project", "TestQuotaProject", "--output_format", "json"},
			"fetch-sts.golden",
			false,
		},
		{
			"fetch; sso; sts",
			[]string{"fetch", "--type", "sso", "--email", "integration/fixtures/fake-ssocli.sh", "--scope", "pubsub", "--ssocli", "sh", "--sts", "--audience", "http://test.com", "--quota_project", "TestQuotaProject", "--output_format", "json"},
			"fetch-sts.golden",
			false,
		},
	}

	processStsOutput := func(sts string) string {
		//STS token differs in every execution even for the same subject token, so we will strip out "access_token" field.
		var jsonData map[string]interface{}
		json.Unmarshal([]byte(sts), &jsonData) // nolint:errcheck
		delete(jsonData, "access_token")
		jsonString, _ := json.Marshal(jsonData)
		return string(jsonString)
	}
	runTestScenariosWithInputAndProcessedOutput(t, tests, nil, processStsOutput)
}

// Test Service Account Impersonation Flow.
// This currently sends request to the real IAM endpoint, which will return 401 for having invalid user access token, which is expected.
func TestServiceAccountImpersonationFlow(t *testing.T) {

	tests := []testCase{
		{
			"fetch; sso; impersonation",
			[]string{"fetch", "--type", "sso", "--email", "integration/fixtures/fake-ssocli.sh", "--scope", "pubsub", "--ssocli", "sh", "--impersonate-service-account", "12345"},
			"fetch-impersonation.golden",
			false,
		},
	}

	processOutput := func(output string) string {
		//Error details are constantly changing, so we will strip out "error.details" field.
		var jsonData map[string]interface{}
		json.Unmarshal([]byte(output), &jsonData) // nolint:errcheck
		delete(jsonData["error"].(map[string]interface{}), "details")
		jsonString, _ := json.Marshal(jsonData)
		return string(jsonString)
	}

	runTestScenariosWithInputAndProcessedOutput(t, tests, nil, processOutput)
}

// getCredentialsFileName finds the credentials filename provided in the testCase arguments.
// If no filename is found, an empty string is returned.
//
// Note: the "--credentials" or "--json" options are used to find the credentials file.
//
// input tc: is the test case.
func getCredentialsFileName(tc *testCase) string {
	var a string
	var i int
	for i, a = range tc.args {
		if a == "--credentials" || a == "--json" {
			break
		}
	}
	if i >= len(tc.args)-1 {
		return ""
	}
	return path.Base(tc.args[i+1])
}

// changeCredentialsFileName replaces the credentials filename in the test arguments.
// If the credentials file is not found, no changes are made.
//
// input tc: is the test case.
// input filename: is the new filename.
func changeCredentialsFileName(tc *testCase, filename string) {
	var a string
	var i int
	for i, a = range tc.args {
		if a == "--credentials" || a == "--json" {
			break
		}
	}
	if i >= len(tc.args)-1 {
		return
	}
	dir := path.Dir(tc.args[i+1])
	tc.args[i+1] = dir + "/" + filename
}

func readFile(path string) string {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Printf("could not read file %s: %v", path, err)
	}
	return string(content)
}

func MockTokenApi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := readFile("integration/fixtures/mock-token-response.json")
	fmt.Fprint(w, response)
}

func MockExpiredTokenApi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := readFile("integration/fixtures/mock-expired-token-response.json")
	fmt.Fprint(w, response)
}

func MockCurlApi(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := "{}"
	fmt.Fprint(w, response)
}

// Compiles oauth2l and executes integration tests.
// Launches a mock API server on localhost to service test requests.
func TestMain(m *testing.M) {
	err := os.Chdir("..")
	if err != nil {
		fmt.Printf("could not change dir: %v", err)
		os.Exit(1)
	}

	abs, err := filepath.Abs(binaryName)

	if err != nil {
		fmt.Printf("could not get abs path for %s: %v", binaryName, err)
		os.Exit(1)
	}

	binaryPath = abs

	if err := exec.Command("go", "build").Run(); err != nil {
		fmt.Printf("could not make binary for %s: %v", binaryName, err)
		os.Exit(1)
	}

	// Start mock server
	go func() {
		mux := http.NewServeMux()
		server := http.Server{Addr: "localhost:8080", Handler: mux}
		mux.HandleFunc("/token", MockTokenApi)
		mux.HandleFunc("/expiredtoken", MockExpiredTokenApi)
		mux.HandleFunc("/curl", MockCurlApi)
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("could not listen on port 8080 %v", err)
		}
	}()

	status := m.Run()

	os.Remove(binaryPath)
	os.Exit(status)
}
