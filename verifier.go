package keycloaklib

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

type KeycloakVerifier struct {
	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider
	config   *Config
}

type TokenClaims struct {
	Sub               string                 `json:"sub"`
	Email             string                 `json:"email"`
	EmailVerified     bool                   `json:"email_verified"`
	Name              string                 `json:"name"`
	PreferredUsername string                 `json:"preferred_username"`
	GivenName         string                 `json:"given_name"`
	FamilyName        string                 `json:"family_name"`
	RealmAccess       *RealmAccess           `json:"realm_access,omitempty"`
	ResourceAccess    map[string]*ClientRole `json:"resource_access,omitempty"`
	Groups            []string               `json:"groups,omitempty"`
	Scope             string                 `json:"scope,omitempty"`
	Sid               string                 `json:"sid,omitempty"`
	Azp               string                 `json:"azp,omitempty"`
	SessionState      string                 `json:"session_state,omitempty"`
	Acr               string                 `json:"acr,omitempty"`
	AllowedOrigins    []string               `json:"allowed-origins,omitempty"`
	Iat               int64                  `json:"iat"`
	Exp               int64                  `json:"exp"`
	Typ               string                 `json:"typ,omitempty"`
	Aud               interface{}            `json:"aud,omitempty"`
	Iss               string                 `json:"iss,omitempty"`
	CustomClaims      map[string]interface{} `json:"-"`
}

type RealmAccess struct {
	Roles []string `json:"roles"`
}

type ClientRole struct {
	Roles []string `json:"roles"`
}

func NewKeycloakVerifier(ctx context.Context, config *Config) (*KeycloakVerifier, error) {
	if config == nil {
		return nil, errors.New("config is required")
	}
	if config.URL == emptyString || config.Realm == emptyString {
		return nil, errors.New("URL and Realm are required")
	}

	issuerURL := fmt.Sprintf("%s/realms/%s", config.URL, config.Realm)
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	verifierConfig := &oidc.Config{
		SkipClientIDCheck: true,
	}

	if config.ClientID != emptyString {
		verifierConfig.ClientID = config.ClientID
		verifierConfig.SkipClientIDCheck = false
	}

	verifier := provider.Verifier(verifierConfig)

	return &KeycloakVerifier{
		verifier: verifier,
		provider: provider,
		config:   config,
	}, nil
}

func (kv *KeycloakVerifier) ValidateToken(ctx context.Context, rawToken string) (*oidc.IDToken, error) {
	if rawToken == emptyString {
		return nil, errors.New("token is empty")
	}
	return kv.verifier.Verify(ctx, rawToken)
}

func (kv *KeycloakVerifier) ValidateAccessToken(ctx context.Context, rawToken string) (*TokenClaims, error) {
	if rawToken == emptyString {
		return nil, errors.New("token is empty")
	}

	idToken, err := kv.verifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify token: %w", err)
	}

	return kv.ExtractClaims(idToken)
}

func (kv *KeycloakVerifier) ExtractClaims(token *oidc.IDToken) (*TokenClaims, error) {
	var claims TokenClaims
	if err := token.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	var allClaims map[string]interface{}
	if err := token.Claims(&allClaims); err == nil {
		claims.CustomClaims = make(map[string]interface{})
		standardFields := map[string]bool{
			"sub": true, "email": true, "email_verified": true, "name": true,
			"preferred_username": true, "given_name": true, "family_name": true,
			"realm_access": true, "resource_access": true, "groups": true,
			"scope": true, "sid": true, "azp": true, "session_state": true,
			"acr": true, "allowed-origins": true, "iat": true, "exp": true,
			"typ": true, "aud": true, "iss": true,
		}
		for k, v := range allClaims {
			if !standardFields[k] {
				claims.CustomClaims[k] = v
			}
		}
	}

	return &claims, nil
}

func (tc *TokenClaims) HasRealmRole(role string) bool {
	if tc.RealmAccess == nil {
		return false
	}
	for _, r := range tc.RealmAccess.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func (tc *TokenClaims) HasClientRole(clientID, role string) bool {
	if tc.ResourceAccess == nil {
		return false
	}
	clientRoles, exists := tc.ResourceAccess[clientID]
	if !exists {
		return false
	}
	for _, r := range clientRoles.Roles {
		if r == role {
			return true
		}
	}
	return false
}

func (tc *TokenClaims) GetClientRoles(clientID string) []string {
	if tc.ResourceAccess == nil {
		return []string{}
	}
	if clientRoles, exists := tc.ResourceAccess[clientID]; exists {
		return clientRoles.Roles
	}
	return []string{}
}

func (tc *TokenClaims) IsInGroup(group string) bool {
	for _, g := range tc.Groups {
		if g == group {
			return true
		}
	}
	return false
}

func ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == emptyString {
		return emptyString, errors.New("authorization header is empty")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
		return parts[1], nil
	}

	if len(parts) == 1 {
		return parts[0], nil
	}

	return emptyString, errors.New("invalid authorization header format")
}

func (kv *KeycloakVerifier) GetUserInfo(ctx context.Context, accessToken string) (map[string]interface{}, error) {
	userInfoURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", kv.config.URL, kv.config.Realm)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := kv.config.HTTPClient
	if client == nil {
		client = &http.Client{}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get user info: status %d", resp.StatusCode)
	}

	var userInfo map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info: %w", err)
	}

	return userInfo, nil
}
