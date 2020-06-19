package main

import (
	"os/exec"
	"fmt"
	"strings"
)

// WrapperCommand represents components necessary for OAuth2l request
type WrapperCommand struct {
	RequestType string
	Args
}

// Args type used for unmarshalled JSON
type Args map[string]interface{}

// Execute will capture output of OAuth2l CLI using command args
func (wc WrapperCommand) Execute() (output string, err error) {
	// combinedArgs used to represent command arguments in an array
	args, ok := combinedArgs(wc)

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