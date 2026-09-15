package main

import (
	"aws-login/config"
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"syscall"
)

var version = "2.0.4"

func main() {
	var err error
	params := config.Params{
		Cmd:            nil,
		ExtraArgs:      nil,
		Verbose:        flag.Bool("v", false, "More output."),
		Timeout:        flag.Int("t", -1, "STS session duration in `seconds` for every role (overrides config; default 8h, stepped down per role if too long)."),
		Debug:          flag.Bool("d", false, "Full debugging of all API calls (prints credentials in cleartext)."),
		Help:           flag.Bool("h", false, "Show this message and quit (same as --help)."),
		Version:        flag.Bool("version", false, "Print version and quit."),
		Keyring:        flag.Bool("keyring", true, "Use the OS keyring for the password. Pass --keyring=false to always prompt."),
		AutoCompletion: flag.String("autocomplete", "", "Generate a completion script for `shell` (bash or zsh)."),
		ShowConfig:     flag.Bool("show-config", false, "Show the config file path and the loaded configuration as JSON."),
		Passkey:        flag.Bool("passkey", false, "Use Harvard Key passkey login via browser instead of password+MFA."),
		Headed:         flag.Bool("headed", false, "Force a visible browser window for --passkey (skip the headless attempt)."),
	}

	// A custom Usage so -h and --help (handled inside flag.Parse, which exits
	// before our own -h check) both print the commands.
	flag.Usage = printUsage
	if err := checkFlagDashes(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s\nRun 'aws-login --help' for usage.\n", err)
		os.Exit(2)
	}
	flag.Parse()

	if *params.Version {
		fmt.Printf("Version: %s\n", version)
		os.Exit(0)
	}
	if *params.Help {
		printUsage()
		os.Exit(0)
	}

	if *params.Debug {
		fmt.Printf("!! WARNING: Debugging is enabled - this will print ALL network communication INCLUDING CREDENTIALS !!\n")
		fmt.Printf("!! Be sure to scrub whatever you capture in logs to remove your password !!\n")
		fmt.Println("Press <enter> to continue.")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
	}

	remainingArgs := flag.Args()
	if len(remainingArgs) == 0 {
		login := "login"
		params.Cmd = &login
	} else {
		params.Cmd = &remainingArgs[0]
		params.ExtraArgs = remainingArgs[1:]
	}

	if err = config.MigrateLegacyConfig(); err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		os.Exit(1)
	}

	userConfigExists, err := config.UserConfigExists(&params)
	if err != nil {
		fmt.Printf("Error: %s\n", err.Error())
		os.Exit(1)
	}
	if !userConfigExists {
		err = config.CreateEmptyConfigFile(&params, nil)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
	}

	userConfig := config.LoadUserConfig(&params)

	runtimeContext := config.RuntimeContext{
		UserConfig: userConfig,
		Params:     params,
	}

	if *params.AutoCompletion != "" {
		err = generateAutocomplete(runtimeContext)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	} else if *params.ShowConfig {
		err = showConfigJson(runtimeContext)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			syscall.Exit(1)
		}
		os.Exit(0)
	}

	switch *runtimeContext.Params.Cmd {
	case "login":
		err = login(runtimeContext)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			syscall.Exit(1)
		}
		fmt.Printf("Logged in!\n")
		break
	case "login_all":
		err = login_all(runtimeContext)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			syscall.Exit(1)
		}
		fmt.Printf("Logged in!\n")
		break
	case "list":
		err = listRoles(runtimeContext)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			syscall.Exit(1)
		}
		break
	case "list-role-map":
		err = listRoleMap(runtimeContext)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			syscall.Exit(1)
		}
		break
	case "switch":
		if len(runtimeContext.Params.ExtraArgs) == 0 {
			fmt.Printf("Error: switch requires a role name (e.g. `aws-login switch my-profile`)\n")
			os.Exit(1)
		}
		newRoleName := runtimeContext.Params.ExtraArgs[0]
		err = switchRoles(runtimeContext, newRoleName)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			syscall.Exit(1)
		}
		break
	case "configure_keyring":
		err = configureKeyring(runtimeContext)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			syscall.Exit(1)
		}
		break
	case "configure_passkey":
		err = configurePasskey(runtimeContext)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			syscall.Exit(1)
		}
		break
	case "forget_passkey":
		err = forgetPasskey(runtimeContext)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			syscall.Exit(1)
		}
		break
	case "assume":
		err = assumeRole(runtimeContext)
		if err != nil {
			fmt.Printf("Error: %s\n", err.Error())
			syscall.Exit(1)
		}
		break
	default:
		fmt.Printf("Unknown command: %s\n\n", *runtimeContext.Params.Cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	out := flag.CommandLine.Output()
	fmt.Fprintf(out, "Usage: aws-login [flags] [command] [args]\n\n")
	fmt.Fprintf(out, "Commands:\n")
	fmt.Fprintf(out, "  login [profile]     Log in to ALL saved profiles (profile_map). With a profile, also make it [default]. (default command)\n")
	fmt.Fprintf(out, "  login_all           Same as `login` with no profile.\n")
	fmt.Fprintf(out, "  list                List the role ARNs you are entitled to (no STS calls).\n")
	fmt.Fprintf(out, "  list-role-map       List the saved profile mapping (role ARN -> profile).\n")
	fmt.Fprintf(out, "  switch <profile>    Make an already-logged-in profile [default] without re-authenticating.\n")
	fmt.Fprintf(out, "  assume <role>       Fetch credentials for an assumable role (assumable_roles).\n")
	fmt.Fprintf(out, "  configure_keyring   Store your password in the OS keyring.\n")
	fmt.Fprintf(out, "  configure_passkey   One-time enrollment of an Okta passkey for unattended --passkey logins.\n")
	fmt.Fprintf(out, "  forget_passkey      Remove the stored passkey credential from the OS keyring.\n")
	fmt.Fprintf(out, "\nFlags:\n")
	// flag.PrintDefaults prints every flag with one dash; print our convention instead.
	flag.VisitAll(func(f *flag.Flag) {
		argName, usage := flag.UnquoteUsage(f)
		spec := flagSpelling(f.Name)
		if argName != "" {
			spec += " " + argName
		}
		if f.DefValue != "" && f.DefValue != "false" && f.DefValue != "-1" {
			usage += fmt.Sprintf(" (default %s)", f.DefValue)
		}
		fmt.Fprintf(out, "  %-22s %s\n", spec, usage)
	})
	fmt.Fprintf(out, "\nConfig file: %s\n", *config.GetConfigFileName(nil))
}

// flagSpelling returns the documented spelling of a flag: -x for single-letter
// flags, --name for everything else.
func flagSpelling(name string) string {
	if len(name) == 1 {
		return "-" + name
	}
	return "--" + name
}

// checkFlagDashes enforces flagSpelling on the command line. Go's flag package
// accepts both -name and --name, so without this -passkey and --v would work
// but be undocumented. Scanning stops at the first non-flag (the command) or
// "--"; unknown flags are left for flag.Parse to report.
func checkFlagDashes(args []string) error {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || arg == "-" || !strings.HasPrefix(arg, "-") {
			return nil
		}
		name := strings.TrimLeft(arg, "-")
		dashes := len(arg) - len(name)
		hasValue := false
		if eq := strings.IndexByte(name, '='); eq >= 0 {
			name, hasValue = name[:eq], true
		}
		f := flag.Lookup(name)
		if f == nil && name != "help" {
			return nil
		}
		if want := flagSpelling(name); dashes != len(want)-len(name) {
			return fmt.Errorf("use %s, not %s", want, strings.Repeat("-", dashes)+name)
		}
		if f != nil && !hasValue && !isBoolFlag(f) {
			i++ // skip the flag's separate value, e.g. "-t 3600"
		}
	}
	return nil
}

func isBoolFlag(f *flag.Flag) bool {
	bf, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && bf.IsBoolFlag()
}
