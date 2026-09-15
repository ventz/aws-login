package credential

import (
    "github.com/zalando/go-keyring"
)

const (
    // ServiceName is the service name used for storing credentials
    ServiceName = "aws-login-saml-cli"
)

// GetPassword retrieves a password from the system keyring
// Returns empty string if password is not found
func GetPassword(username string) string {
    password, err := keyring.Get(ServiceName, username)
    if err != nil {
        // Return empty string if password not found or any error occurs
        return ""
    }
    return password
}

// StorePassword saves a password to the system keyring
// Returns error if storage fails
func StorePassword(username, password string) error {
    return keyring.Set(ServiceName, username, password)
}

// DeletePassword removes a password from the system keyring
func DeletePassword(username string) error {
    return keyring.Delete(ServiceName, username)
}