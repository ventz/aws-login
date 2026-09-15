package aws

import (
	"aws-login/config"
	"fmt"
	aws_config "github.com/aws/aws-sdk-go-v2/config"
	"github.com/google/uuid"
	"golang.org/x/net/context"
	"gopkg.in/ini.v1"
	"os"
	"time"
)

func AwsConfigFileName() string {
	homeDir, _ := os.UserHomeDir()
	return fmt.Sprintf("%s/.aws/config", homeDir)
}
func AwsCredentialsFileName() string {
	homeDir, _ := os.UserHomeDir()
	return fmt.Sprintf("%s/.aws/credentials", homeDir)
}

func LoadAwsConfig() error {
	config, err := aws_config.LoadDefaultConfig(context.Background())
	if err != nil {
		fmt.Println("Error loading AWS config:", err)
		return err
	}

	fmt.Println("AWS config loaded successfully: ", config.Region)

	return nil
}
func EnsureAwsDirExists() {
	// Ensure the AWS directory exists
	homeDir, _ := os.UserHomeDir()
	awsDir := fmt.Sprintf("%s/.aws", homeDir)
	if _, err := os.Stat(awsDir); os.IsNotExist(err) {
		err := os.Mkdir(awsDir, 0700)
		if err != nil {
			fmt.Printf("Error creating ~/.aws directory: %v\n", err)
			panic(err)
		}
	}
}

func GetAwsConfigFile() (*ini.File, error) {
	cfg, err := ini.Load(AwsConfigFileName())
	if err != nil {
		fmt.Printf("Failed to read file: %v", err)
		return nil, err
	}

	return cfg, nil
}

func GetAwsCredentialsFile() (*ini.File, error) {
	cfg, err := ini.Load(AwsCredentialsFileName())
	if err != nil {
		fmt.Printf("Failed to read file: %v", err)
		return nil, err
	}

	return cfg, nil
}

// Adds the credentials to the ~/.aws/credentials file.
func AddAwsCredentialsAssumedRole(runtimeContext config.RuntimeContext, roleAlias string, assumedCredentials *AwsCredentials) {
	EnsureAwsDirExists()

	awsCredentialsFile, err := GetAwsCredentialsFile()
	if err != nil {
		fmt.Printf("Error reading credentials file: %v", err)
		panic(err)
	}
	awsConfigFile, err := GetAwsConfigFile()
	if err != nil {
		fmt.Printf("Error reading aws config file: %v", err)
		panic(err)
	}

	// This is a ridiculous workaround for the fact that the library uses the section name "DEFAULT"
	// as the top-level section name and this collides with OCI using it as a section name. It therefore deletes that
	// section if this isn't set to something different.
	ini.DEFAULT_SECTION = uuid.New().String()
	ini.DefaultSection = uuid.New().String()

	// Save the credentials to the credentials file
	addAwsCredential(awsCredentialsFile, awsConfigFile, roleAlias, *assumedCredentials)

	err = awsCredentialsFile.SaveTo(AwsCredentialsFileName())
	if err != nil {
		panic(err)
	}
}
func SaveAwsCredentials(runtimeContext config.RuntimeContext, credentials []AwsCredentials, defaultCredential *AwsCredentials) {

	EnsureAwsDirExists()

	awsCredentialsFile, err := GetAwsCredentialsFile()
	if err != nil {
		fmt.Printf("Error reading credentials file: %v", err)
		panic(err)
	}
	awsConfigFile, err := GetAwsConfigFile()
	if err != nil {
		fmt.Printf("Error reading aws config file: %v", err)
		panic(err)
	}

	// This is a ridiculous workaround for the fact that the library uses the section name "DEFAULT"
	// as the top-level section name and this collides with OCI using it as a section name. It therefore deletes that
	// section if this isn't set to something different.
	ini.DEFAULT_SECTION = uuid.New().String()
	ini.DefaultSection = uuid.New().String()

	// If the user provided a default credsential set it.
	if defaultCredential != nil {
		fmt.Printf("Logging in to %s\n", defaultCredential.RoleArn)
		// Save the credentials to the credentials file
		addAwsCredential(awsCredentialsFile, awsConfigFile, "default", *defaultCredential)
	}

	// Set the other mapped profiles
	for _, credential := range credentials {
		configProfile, ok := runtimeContext.UserConfig.ProfileMap[credential.RoleArn]
		if ok {
			if *runtimeContext.Params.Verbose {
				fmt.Printf("Creating profile %s->%s\n", configProfile, credential.RoleArn)
			}
			addAwsCredential(awsCredentialsFile, awsConfigFile, configProfile, credential)
		}
	}

	err = awsCredentialsFile.SaveTo(AwsCredentialsFileName())
	if err != nil {
		panic(err)
	}
}

func addAwsCredential(awsCredentialsFile *ini.File, awsConfigFile *ini.File, profile string, credential AwsCredentials) {
	var configProfile string
	if profile != "default" {
		configProfile = "profile " + profile
	} else {
		configProfile = profile
	}

	// Ensure we have a config entry for this profile.
	configSection := awsConfigFile.Section(configProfile)
	// TODO: This should technically not be hard-coded.... But practically speaking this is always the value we use.
	configSection.Key("region").SetValue("us-east-1")

	// Save the credentials to the credentials file
	credentialsSection := awsCredentialsFile.Section(profile)
	credentialsSection.Key("aws_access_key_id").SetValue(credential.AccessKeyId)
	credentialsSection.Key("aws_secret_access_key").SetValue(credential.SecretAccessKey)
	credentialsSection.Key("aws_session_token").SetValue(credential.SessionToken)
	if credential.Expiration != nil {
		credentialsSection.Key("aws_session_expiration").SetValue(credential.Expiration.UTC().Format(time.RFC3339))
	}
}
