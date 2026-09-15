package credential

import (
	"encoding/json"

	"github.com/zalando/go-keyring"
)

// passkeyKeyringUser is the keyring "username" slot we use to store the
// passkey credential blob. The service name is reused from ServiceName so
// all aws-login secrets live under one keyring service entry.
const passkeyKeyringUser = "passkey-credential"

// PasskeyCredential is the on-disk shape of a WebAuthn credential captured
// during enrollment, suitable for re-injecting into a CDP virtual
// authenticator on subsequent unattended logins.
//
// Field names match Chrome DevTools Protocol's WebAuthn.Credential type so we
// can serialize/deserialize via the same JSON the browser produces.
type PasskeyCredential struct {
	CredentialID         string `json:"credentialId"`
	RpID                 string `json:"rpId"`
	PrivateKey           string `json:"privateKey"` // ECDSA P-256, PKCS#8 DER, base64
	SignCount            int64  `json:"signCount"`
	IsResidentCredential bool   `json:"isResidentCredential"`
	UserHandle           string `json:"userHandle,omitempty"`
}

// GetPasskeyCredential returns the stored passkey credential or nil if none
// is set. An empty-string or missing keyring entry is treated as "not set"
// (not an error) so callers can fall back to interactive auth cleanly.
func GetPasskeyCredential() *PasskeyCredential {
	raw, err := keyring.Get(ServiceName, passkeyKeyringUser)
	if err != nil || raw == "" {
		return nil
	}
	var cred PasskeyCredential
	if jsonErr := json.Unmarshal([]byte(raw), &cred); jsonErr != nil {
		return nil
	}
	return &cred
}

// StorePasskeyCredential writes the credential to the OS keyring as JSON.
func StorePasskeyCredential(cred *PasskeyCredential) error {
	buf, err := json.Marshal(cred)
	if err != nil {
		return err
	}
	return keyring.Set(ServiceName, passkeyKeyringUser, string(buf))
}

// DeletePasskeyCredential removes any stored passkey credential.
func DeletePasskeyCredential() error {
	return keyring.Delete(ServiceName, passkeyKeyringUser)
}
