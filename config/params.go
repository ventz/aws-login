package config

import (
	"fmt"
)

type Params struct {
	Cmd            *string
	Verbose        *bool
	Timeout        *int
	Debug          *bool
	Help           *bool
	Version        *bool
	Keyring        *bool
	AutoCompletion *string
	ShowConfig     *bool
	Passkey        *bool
	Headed         *bool

	ExtraArgs []string
}

type RuntimeContext struct {
	UserConfig UserConfig
	Params     Params
}

func (a *Params) Show() string {
	line := ""
	line += fmt.Sprintf("cmd: %v\n", *a.Cmd)
	line += fmt.Sprintf("verbose: %v\n", *a.Verbose)
	line += fmt.Sprintf("debug: %v\n", *a.Debug)
	return line
}
