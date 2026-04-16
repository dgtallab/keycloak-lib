package keycloaklib

import (
	"context"
	"fmt"
	"net/http"
)

// GenerateMagicLink generates a one-time login link for the given email address.
// The link is returned as a string and is never sent by email (SendEmail is forced to false).
func (ka *KeycloakClient) GenerateMagicLink(ctx context.Context, req MagicLinkRequest) (string, error) {
	if req.Email == emptyString || req.ClientID == emptyString || req.RedirectURI == emptyString {
		return "", ka.errorf(ErrUsernameAndEmailRequired)
	}
	req.SendEmail = false

	path := fmt.Sprintf("/admin/realms/%s/magic-link", ka.config.Realm)

	var resp MagicLinkResponse
	err := ka.doRequest(ctx, http.MethodPost, path, req, &resp)
	if err != nil {
		return "", err
	}

	if resp.Link == emptyString {
		return "", ka.errorf(ErrFailedToGenerateMagicLink, "no link in response")
	}

	return resp.Link, nil
}
