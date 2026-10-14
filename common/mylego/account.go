package mylego

import (
	"crypto"

	"github.com/go-acme/lego/v5/acme"
)

// 保留现有 account.json 的 body/uri 格式。
type accountRegistration struct {
	Body acme.Account `json:"body"`
	URI  string       `json:"uri,omitempty"`
}

// Account represents a users local saved credentials.
type Account struct {
	Email        string               `json:"email"`
	Registration *accountRegistration `json:"registration"`
	key          crypto.Signer
}

/** Implementation of the registration.User interface **/

// GetEmail returns the email address for the account.
func (a *Account) GetEmail() string {
	return a.Email
}

// GetPrivateKey returns the private RSA account key.
func (a *Account) GetPrivateKey() crypto.Signer {
	return a.key
}

// GetRegistration returns the server registration.
func (a *Account) GetRegistration() *acme.ExtendedAccount {
	if a.Registration == nil {
		return nil
	}
	return &acme.ExtendedAccount{Account: a.Registration.Body, Location: a.Registration.URI}
}

/** End **/
