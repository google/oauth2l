package api

import (
	"os/exec"
)

type Wrapper struct {
	RequestType string
	Flags []string
	FlagValues []string
}

