package keycloaklib

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"
)

type PKCEParams struct {
	CodeVerifier  string
	CodeChallenge string
}
type SocialLoginOptions struct {
	Provider    string
	RedirectURI string
	Scopes      []string
	State       string
	PKCE        *PKCEParams
}

func GeneratePKCE() (*PKCEParams, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf(translations[DefaultLanguage][ErrFailedToGeneratePKCE], err)
	}
	verifier := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	return &PKCEParams{
		CodeVerifier:  verifier,
		CodeChallenge: challenge,
	}, nil
}

func GenerateState() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf(translations[DefaultLanguage][ErrFailedToGenerateState], err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (ka *KeycloakClient) GetSocialLoginURL(opts SocialLoginOptions) (string, error) {
	if opts.Provider == emptyString {
		return emptyString, ka.errorf(ErrSocialProviderRequired)
	}
	if opts.RedirectURI == emptyString {
		return emptyString, ka.errorf(ErrRedirectURIRequired)
	}
	if opts.State == emptyString {
		return emptyString, ka.errorf(ErrStateRequired)
	}

	clientID := ka.config.ClientID
	if ka.config.PublicClientID != emptyString {
		clientID = ka.config.PublicClientID
	}

	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	authURL := fmt.Sprintf(
		"%s/realms/%s/protocol/openid-connect/auth",
		ka.config.URL, ka.config.Realm,
	)

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", opts.RedirectURI)
	params.Set("scope", strings.Join(scopes, " "))
	params.Set("state", opts.State)
	params.Set("kc_idp_hint", opts.Provider)

	if opts.PKCE != nil {
		params.Set("code_challenge", opts.PKCE.CodeChallenge)
		params.Set("code_challenge_method", "S256")
	}

	return authURL + "?" + params.Encode(), nil
}

func (ka *KeycloakClient) ExchangeSocialLoginCode(ctx context.Context, code, redirectURI, codeVerifier string) (*oauth2.Token, error) {
	if code == emptyString {
		return nil, ka.errorf(ErrUsernamePasswordRequired)
	}
	if redirectURI == emptyString {
		return nil, ka.errorf(ErrRedirectURIRequired)
	}

	clientID := ka.config.ClientID
	if ka.config.PublicClientID != emptyString {
		clientID = ka.config.PublicClientID
	}

	tokenURL := buildTokenURL(ka.config.URL, ka.config.Realm, ka.config.TokenEndpoint)

	params := TokenRequestParams{
		GrantType:    "authorization_code",
		ClientID:     clientID,
		Code:         code,
		RedirectURI:  redirectURI,
		CodeVerifier: codeVerifier,
	}
	if ka.config.ClientSecret != emptyString && ka.config.PublicClientID == emptyString {
		params.ClientSecret = ka.config.ClientSecret
	}

	body, statusCode, err := requestTokenWithStatus(ctx, ka.client, tokenURL, params, ka.language)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, ka.errorf(ErrFailedToObtainLoginToken, statusCode, string(body))
	}

	var token oauth2.Token
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, ka.errorf(ErrFailedToParseToken, err)
	}
	if token.AccessToken == emptyString {
		return nil, ka.errorf(ErrNoAccessToken)
	}

	return &token, nil
}
