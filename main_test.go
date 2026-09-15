package main

import (
	"flag"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	flag.Bool("passkey", false, "")
	flag.Bool("keyring", true, "")
	flag.Bool("v", false, "")
	flag.Int("t", -1, "")
	flag.String("autocomplete", "", "")
	os.Exit(m.Run())
}

func TestCheckFlagDashes(t *testing.T) {
	cases := []struct {
		args    []string
		wantErr bool
	}{
		{[]string{"--passkey", "login"}, false},
		{[]string{"-v", "-t", "3600", "--passkey", "login"}, false},
		{[]string{"-t=3600", "--keyring=false", "login", "entarch"}, false},
		{[]string{"--autocomplete", "zsh"}, false},
		{[]string{"--help"}, false},
		{[]string{"login", "-passkey"}, false}, // after the command: not a flag
		{[]string{"--unknown"}, false},         // left for flag.Parse to report
		{[]string{"-passkey", "login"}, true},
		{[]string{"-keyring=false"}, true},
		{[]string{"-help"}, true},
		{[]string{"--v"}, true},
		{[]string{"-t", "3600", "-passkey"}, true},
	}
	for _, c := range cases {
		err := checkFlagDashes(c.args)
		if (err != nil) != c.wantErr {
			t.Errorf("checkFlagDashes(%q) error = %v, wantErr %v", c.args, err, c.wantErr)
		}
	}
}
