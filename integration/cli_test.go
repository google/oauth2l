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
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
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

// Runs test cases where stdin input is needed and output needs to be processed before comparing to golden files.
func runTestScenariosWithInputAndProcessedOutput(t *testing.T, tests []testCase, input *os.File, processOutput processOutput) {
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(binaryPath, tc.args...)

			if input != nil {
				cmd.Stdin = input
			}

			output, err := cmd.CombinedOutput()
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
			"no-audience.golden",
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
	}
	runTestScenariosWithInput(t, tests, newFixture(t, "fake-verification-code.fixture").asFile())
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

// Test SSO Flow. Uses "echo" as a fake ssocli to return the calling parameters instead of an actual token.
func TestSSOFlow(t *testing.T) {
	tests := []testCase{
		{
			"fetch; sso",
			[]string{"fetch", "--type", "sso", "--email", "example@example.com", "--scope", "pubsub", "--ssocli", "echo"},
			"fetch-sso.golden",
			false,
		},
		{
			"fetch; sso; old interface",
			[]string{"fetch", "--sso", "--ssocli", "echo", "example@example.com", "pubsub"},
			"fetch-sso.golden",
			false,
		},
	}
	runTestScenarios(t, tests)
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
		server := http.Server{Addr: ":8080", Handler: mux}
		mux.HandleFunc("/token", MockTokenApi)
		mux.HandleFunc("/curl", MockCurlApi)
		if err := server.ListenAndServe(); err != nil {
			fmt.Printf("could not listen on port 8080 %v", err)
		}
	}()

	status := m.Run()

	os.Remove(binaryPath)
	os.Exit(status)
}
