package zoho

import (
	"github.com/zitadel/oidc/v3/pkg/client/rp"

	"github.com/zitadel/zitadel/internal/idp/providers/oidc"
)

// Provider implements the Provider interface for Zoho
type Provider struct {
	*oidc.Provider
}

// New creates a new Zoho Identity Provider
func New(name, issuer, clientID, clientSecret, redirectURI string, scopes []string, opts ...ProviderOptions) (*Provider, error) {
	options := make([]oidc.ProviderOpts, 0)
	options = append(options, oidc.WithConsent())
	
	// Apply custom options
	o := providerOptions{
		idTokenMapping: false,
		pkce:           false,
	}
	for _, opt := range opts {
		opt(&o)
	}
	
	if o.idTokenMapping {
		options = append(options, oidc.WithIDTokenMapping())
	}
	
	if o.pkce {
		options = append(options, oidc.WithRelyingPartyOption(rp.WithPKCE(nil)))
	}
	
	provider, err := oidc.New(
		name,
		issuer,
		clientID,
		clientSecret,
		redirectURI,
		scopes,
		oidc.DefaultMapper,
		options...,
	)
	
	if err != nil {
		return nil, err
	}
	
	return &Provider{
		Provider: provider,
	}, nil
}

// NewSession creates a new Zoho session
func NewSession(provider *oidc.Provider, code string, idpArguments map[string]any) *oidc.Session {
	return oidc.NewSession(provider, code, idpArguments)
}

type providerOptions struct {
	idTokenMapping bool
	pkce           bool
}

// ProviderOptions configures the provider
type ProviderOptions func(*providerOptions)

// WithIDTokenMapping enables mapping from ID token claims
func WithIDTokenMapping() ProviderOptions {
	return func(o *providerOptions) {
		o.idTokenMapping = true
	}
}

// WithPKCE enables PKCE for the authorization flow
func WithPKCE() ProviderOptions {
	return func(o *providerOptions) {
		o.pkce = true
	}
} 