package keycloaklib

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

func buildTokenURL(baseURL, realm string, customEndpoint string) string {
	if customEndpoint != "" {
		return customEndpoint
	}
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", baseURL, realm)
}

func makeFormRequest(ctx context.Context, httpClient *http.Client, endpoint string, data url.Values, lang string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, 0, makeError(lang, ErrFailedToCreateRequest, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, makeError(lang, ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, makeError(lang, ErrFailedToReadResponse, err)
	}

	return body, resp.StatusCode, nil
}

func requestToken(ctx context.Context, httpClient *http.Client, tokenURL string, params TokenRequestParams, lang string) ([]byte, error) {
	body, statusCode, err := requestTokenWithStatus(ctx, httpClient, tokenURL, params, lang)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, makeError(lang, ErrFailedToGetToken, statusCode, body)
	}
	return body, nil
}

func requestTokenWithStatus(ctx context.Context, httpClient *http.Client, tokenURL string, params TokenRequestParams, lang string) ([]byte, int, error) {
	data := url.Values{}
	data.Set("grant_type", params.GrantType)
	data.Set("client_id", params.ClientID)

	if params.ClientSecret != "" {
		data.Set("client_secret", params.ClientSecret)
	}
	if params.Username != "" {
		data.Set("username", params.Username)
	}
	if params.Password != "" {
		data.Set("password", params.Password)
	}
	if params.RefreshToken != "" {
		data.Set("refresh_token", params.RefreshToken)
	}
	if params.Code != "" {
		data.Set("code", params.Code)
	}
	if params.RedirectURI != "" {
		data.Set("redirect_uri", params.RedirectURI)
	}
	if params.DeviceCode != "" {
		data.Set("device_code", params.DeviceCode)
	}
	if len(params.Scopes) > 0 {
		data.Set("scope", strings.Join(params.Scopes, " "))
	}
	if params.CodeVerifier != "" {
		data.Set("code_verifier", params.CodeVerifier)
	}

	return makeFormRequest(ctx, httpClient, tokenURL, data, lang)
}

func requestTokenWithOAuth2Response(ctx context.Context, httpClient *http.Client, tokenURL string, params TokenRequestParams, lang string) (*oauth2.Token, error) {
	body, err := requestToken(ctx, httpClient, tokenURL, params, lang)
	if err != nil {
		return nil, err
	}

	var token oauth2.Token
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, makeError(lang, ErrFailedToParseToken, err)
	}

	if token.AccessToken == "" {
		return nil, makeError(lang, ErrNoAccessToken)
	}

	return &token, nil
}

func requestTokenWithTokenResponse(ctx context.Context, httpClient *http.Client, tokenURL string, params TokenRequestParams, lang string) (*tokenResponse, error) {
	body, err := requestToken(ctx, httpClient, tokenURL, params, lang)
	if err != nil {
		return nil, err
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, makeError(lang, ErrFailedToParseToken, err)
	}

	if tok.AccessToken == emptyString {
		return nil, makeError(lang, ErrNoAccessToken)
	}

	return &tok, nil
}

func getClientToken(ctx context.Context, config *Config, lang string) (*tokenResponse, error) {
	tokenURL := buildTokenURL(config.URL, config.Realm, config.TokenEndpoint)
	params := TokenRequestParams{
		GrantType:    "client_credentials",
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
	}
	return requestTokenWithTokenResponse(ctx, config.HTTPClient, tokenURL, params, lang)
}

func (ka *KeycloakClient) refreshAdminToken(ctx context.Context) (*tokenResponse, error) {
	refreshToken := ka.refreshToken

	if refreshToken == emptyString {
		return nil, ka.errorf(ErrNoRefreshToken)
	}

	tokenURL := buildTokenURL(ka.config.URL, ka.config.Realm, ka.config.TokenEndpoint)
	params := TokenRequestParams{
		GrantType:    "refresh_token",
		ClientID:     ka.config.ClientID,
		ClientSecret: ka.config.ClientSecret,
		RefreshToken: refreshToken,
	}

	body, statusCode, err := requestTokenWithStatus(ctx, ka.client, tokenURL, params, ka.language)
	if err != nil {
		return nil, err
	}
	if statusCode != http.StatusOK {
		return nil, ka.errorf(ErrFailedToRefreshToken, statusCode, body)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, ka.errorf(ErrFailedToParseToken, err)
	}
	if tok.AccessToken == emptyString {
		return nil, ka.errorf(ErrNoAccessTokenInRefresh)
	}

	return &tok, nil
}

func (ka *KeycloakClient) ensureTokenValid(ctx context.Context) error {
	ka.mu.RLock()
	if time.Now().Before(ka.expiry) {
		ka.mu.RUnlock()
		return nil
	}
	ka.mu.RUnlock()

	ka.mu.Lock()
	defer ka.mu.Unlock()

	if time.Now().Before(ka.expiry) {
		return nil
	}

	tok, err := ka.refreshAdminToken(ctx)
	if err == nil && tok != nil {
		ka.accessToken = tok.AccessToken
		ka.refreshToken = tok.RefreshToken
		ka.expiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Add(-30 * time.Second)
		return nil
	}

	tok, err = getClientToken(ctx, ka.config, ka.language)
	if err != nil {
		return ka.errorf(ErrTokenRefreshFailed, err)
	}

	ka.accessToken = tok.AccessToken
	ka.refreshToken = tok.RefreshToken
	ka.expiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Add(-30 * time.Second)
	return nil
}
