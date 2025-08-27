package keycloaklib

import (
	"context"
	"errors"
	"github.com/coreos/go-oidc/v3/oidc"
)

type KeycloakVerifier struct {
	verifier *oidc.IDTokenVerifier
}

func (kv *KeycloakVerifier) ValidateToken(ctx context.Context, rawToken string) (*oidc.IDToken, error) {
	if rawToken == "" {
		return nil, errors.New("token is empty")
	}
	return kv.verifier.Verify(ctx, rawToken)
}
