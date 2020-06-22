package main

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// WrapperCommand represents components necessary for OAuth2l request
type WrapperCommand struct {
	RequestType string
	Args
	Credential
}

// Args type used for unmarshalled JSON
type Args map[string]interface{}

// Credential type used for storing JSON-formatted credentials
type Credential map[string]interface{}

// Execute will capture output of OAuth2l CLI using command args
func (wc WrapperCommand) Execute() (output string, err error) {
	// combinedArgs used to represent command arguments in an array
	args, ok := combinedArgs(wc)

	if wc.Credential != nil {
		descriptor, err := allocateMemFile(wc.Credential)

		if err != nil {
			return "", err
		}

		path := getCredentialPath(descriptor)

		args = append(args, "--credentials", path)
	}

	if !ok {
		return "", fmt.Errorf("invalid type found in args")
	}

	// Execute command and capture output
	command := exec.Command("oauth2l", args...)
	byteBuffer, err := command.Output()

	// Convert byteBuffer to string and remove newline character
	output = strings.TrimSuffix(string(byteBuffer), "\n")
	
	return
}

func allocateMemFile(credential Credential) (descriptor int, err error) {
	credStr, err := json.Marshal(credential)

	if err != nil {
		return 0, err
	}

	byteArray := []byte(credStr)

	descriptor, err = unix.MemfdCreate("credential", 0)

	if err != nil {
		return 0, err
	}

	err = unix.Ftruncate(descriptor, int64(len(byteArray)))
	if err != nil {
		return 0, err
	}

	data, err := unix.Mmap(descriptor, 0, len(byteArray), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return 0, err
	}

	copy(data, byteArray)

	err = unix.Munmap(data)
	if err != nil {
		return 0, err
	}

	return descriptor, nil
}

func getCredentialPath(descriptor int) (path string) {
	return fmt.Sprintf("/proc/self/fd/%d", descriptor)
}

// Returns args in flattened array
func combinedArgs(wc WrapperCommand) (combinedArgs []string, ok bool) {
	combinedArgs = append(combinedArgs, wc.RequestType)

	for flag, value := range wc.Args {
		combinedArgs = append(combinedArgs, flag)
		
		// Assert args are of accepted types
		switch value := value.(type) {
		case []string:
			combinedArgs = append(combinedArgs, value...)
		case string:
			combinedArgs = append(combinedArgs, value)
		case []interface{}:
			for _, subValue := range value {
				combinedArgs = append(combinedArgs, subValue.(string))
			}
		default:
			return nil, false
		}
	}
	return combinedArgs, true
}