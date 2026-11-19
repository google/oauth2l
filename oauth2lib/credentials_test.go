//
// Copyright 2026 Google LLC
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

package oauth2lib

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestConfigFormattingHidesJSON(t *testing.T) {
	cfg := Config{
		JSON:     userJSON(t, map[string]any{"refresh_token": "secret-refresh"}),
		Scopes:   []string{"a"},
		TokenURL: "https://oauth2.googleapis.com/token",
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("cfg", "config", cfg, "ptr", &cfg)

	for name, got := range map[string]string{
		"%v":      fmt.Sprintf("%v", cfg),
		"%+v":     fmt.Sprintf("%+v", cfg),
		"%#v":     fmt.Sprintf("%#v", cfg),
		"%v_ptr":  fmt.Sprintf("%v", &cfg),
		"%#v_ptr": fmt.Sprintf("%#v", &cfg),
		"slog":    logs.String(),
	} {
		if strings.Contains(got, "secret-refresh") || strings.Contains(got, "client-secret") {
			t.Errorf("%s output %q contains a secret from Config.JSON", name, got)
		}
		if !strings.Contains(got, "oauth2.googleapis.com") {
			t.Errorf("%s output %q is missing TokenURL", name, got)
		}
	}
}
