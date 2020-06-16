package api

import (
	"os/exec"
	"fmt"
)

// WrapperCommand represents components necessary for OAuth2l request
type WrapperCommand struct {
	RequestType string
	Args map[string]interface{}  // Type used to unmarshal JSON
}

// Execute will capture output of OAuth2l CLI using command args
func (wc WrapperCommand) Execute() (output []byte, err error) {
	// combinedArgs used to represent command arguments in an array
	args, ok := combinedArgs(wc)

	if !ok {
		return nil, fmt.Errorf("invalid type found in args")
	}

	// Execute command and capture output
	command := exec.Command("oauth2l", args...)
	output, err = command.Output()
	return
}

// Returns proper args in order based on command type
func combinedArgs(wc WrapperCommand) (combinedArgs []string, ok bool) {
	for flag, value := range wc.Args {
		combinedArgs = append(combinedArgs, flag)
		
		// Assert args are of type string or []string
		switch value := value.(type) {
		case []string:
			combinedArgs = append(combinedArgs, value...)
		case string:
			combinedArgs = append(combinedArgs, value)
		default:
			return nil, false
		}
	}
	return combinedArgs, true
}
