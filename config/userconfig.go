package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// UserConfig Example config
//
//	{
//	 "username": "user@harvard.edu",
//	 "profile_map": {
//	   "arn:aws:iam::111111111111:role/admints-dev-standard-saml-poweruser-iam-role@us-east-1": "admints-dev",
//	   "arn:aws:iam::333333333333:role/campussvcs-dev-standard-saml-poweruser-iam-role@us-east-1": "campus"
//	 },
//	 "assumable_roles": {
//	     "arm-ecs-deploy": {
//	         "arn": "arn:aws:iam::111111111111:role/arm-ecs-deploy-role",
//	         "required_profile": "cloudhacks"
//	     }
//	 },
//	 "role_timeout_secs": {
//	     "admints-dev": 3600,
//	     "campus": 7200
//	 },
//	 "default_timeout_secs": null,
//	 "use_system_keyring": true
//	}
type UserConfig struct {
	Username           *string                      `json:"username"`
	ProfileMap         map[string]string            `json:"profile_map"`
	AssumableRolesMap  map[string]map[string]string `json:"assumable_roles"`
	DefaultTimeoutSecs *int                         `json:"default_timeout_secs"`
	RoleTimeoutSecs    map[string]int               `json:"role_timeout_secs"`
}

func NewUserConfig() *UserConfig {
	return &UserConfig{
		Username:           nil,
		ProfileMap:         make(map[string]string),
		DefaultTimeoutSecs: nil,
		RoleTimeoutSecs:    make(map[string]int),
	}
}

// ConfigDir is ~/.config/huit_aws on every OS — the same directory the passkey
// flow uses for its Chrome profile. (os.UserConfigDir would give
// ~/Library/Application Support on macOS.)
func ConfigDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "huit_aws")
}

// legacyConfigFileName is where older builds kept the config
// (os.UserConfigDir, i.e. ~/Library/Application Support/huit_aws on macOS).
func legacyConfigFileName() string {
	userConfigDir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(userConfigDir, "huit_aws", "config.json")
}

// MigrateLegacyConfig copies the config from the legacy location to
// ~/.config/huit_aws/config.json when only the legacy file exists. The legacy
// file is left in place.
func MigrateLegacyConfig() error {
	newFile := *GetConfigFileName(nil)
	legacyFile := legacyConfigFileName()
	if legacyFile == "" || legacyFile == newFile {
		return nil
	}
	if _, err := os.Stat(newFile); !errors.Is(err, os.ErrNotExist) {
		return nil
	}
	data, err := os.ReadFile(legacyFile)
	if err != nil {
		return nil
	}
	EnsureConfigDirExists()
	if err := os.WriteFile(newFile, data, 0600); err != nil {
		return fmt.Errorf("migrate config %s -> %s: %w", legacyFile, newFile, err)
	}
	fmt.Fprintf(os.Stderr, "Migrated config %s -> %s (old file left in place)\n", legacyFile, newFile)
	return nil
}

func EnsureConfigDirExists() {
	configDir := ConfigDir()
	if err := os.MkdirAll(configDir, 0700); err != nil {
		fmt.Printf("Error creating %s directory: %v\n", configDir, err)
		panic(err)
	}
}

func GetConfigFileName(overrideFileName *string) *string {
	// NOTE: Override for future use as a parameter.
	var filename *string
	var defaultFileName = filepath.Join(ConfigDir(), "config.json")
	if overrideFileName == nil {
		filename = &defaultFileName
	} else {
		filename = overrideFileName
	}
	return filename
}

func LoadUserConfig(params *Params) UserConfig {
	var filename = GetConfigFileName(nil)
	if *params.Verbose {
		fmt.Printf("Loading config file %s\n", *filename)
	}

	config := NewUserConfig()
	configContents, err := os.ReadFile(*filename)
	if err != nil {
		return *config
	}

	err = json.Unmarshal(configContents, &config)
	if err != nil {
		fmt.Printf("Could not parse the config file: %s\n", err)
		panic(err)
	}
	return *config
}

func UserConfigExists(params *Params) (bool, error) {
	var filename = GetConfigFileName(nil)
	var err error

	if _, err = os.Stat(*filename); err == nil {
		if *params.Verbose {
			fmt.Printf("Config file %s exists.\n", *filename)
		}

		return true, nil
	} else if errors.Is(err, os.ErrNotExist) {
		if *params.Verbose {
			fmt.Printf("Config file %s does not exist.\n", *filename)
		}
		return false, nil
	} else {
		if *params.Verbose {
			fmt.Printf("Config file %s error: %s\n", *filename, err.Error())
		}
		return false, err
	}
}

func CreateEmptyConfigFile(params *Params, overrideFileName *string) error {
	var err error
	var filename = GetConfigFileName(overrideFileName)
	if *params.Verbose {
		fmt.Printf("Creating empty config file %s\n", *filename)
	}

	EnsureConfigDirExists()

	data := []byte("{}")
	err = os.WriteFile(*filename, data, 0644)
	if err != nil {
		fmt.Printf("Could not write the config file: %s\n", err)
		return err
	}

	return nil
}

func SaveUserConfig(params *Params, overrideFileName *string, userConfig *UserConfig) error {
	var filename = GetConfigFileName(overrideFileName)
	if *params.Verbose {
		fmt.Printf("Writing to config file %s\n", *filename)
	}

	EnsureConfigDirExists()

	jsonData, err := json.Marshal(userConfig)
	if err != nil {
		fmt.Printf("Could not marshal the config file: %s\n", err)
		return err
	}

	err = os.WriteFile(*filename, jsonData, 0644)
	if err != nil {
		fmt.Printf("Could not write the config file: %s\n", err)
		return err
	}

	return nil
}
