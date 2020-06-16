package api

import (
	"fmt"
	"os/exec"
)

// WrapperCommand represents components necessary for OAuth2l request
type WrapperCommand struct {
	RequestType string
	Args map[string][]string
}

// Execute will capture output of OAuth2l CLI using command args
func (wc WrapperCommand) Execute() (output []byte, err error) {
	// combinedArgs used to represent command option and order args
	args, success := combinedArgs(wc)

	if !success {
		return nil, fmt.Errorf("missing arguments for command type ", wc.RequestType)
	}

	command := exec.Command("oauth2l", args...)
	output, err = command.Output()
	return
}

// Returns proper args in order using command type
func combinedArgs(wc WrapperCommand) (combinedArgs []string, missingArgs bool) {
	if wc.RequestType == "fetch" {
		combinedArgs = append(combinedArgs, "fetch")


	}
}
