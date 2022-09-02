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
// browser implements helper functions to interact with the OS's default
// internet browser. MacOs, Windows and Linux are the only supported OS.
package util

import (
	"fmt"
	"os/exec"
	"runtime"
)

// Browser represents an internet browser.
type Browser struct{}

// Opens URL in a new broser tab.
func (b *Browser) OpenURL(url string) error {
	var err error
	rt := runtime.GOOS
	switch rt {
	case "darwin":
		err = exec.Command("open", url).Start()
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		err = fmt.Errorf("Unsupported runtime")
	}

	if err != nil {
		return fmt.Errorf("Unable to open browser window for runtime, %s: %v", rt, err)
	}
	return nil
}
