package keycloaklib

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

func (ka *KeycloakClient) Login(ctx context.Context, username, password string, scopes []string) (*oauth2.Token, error) {
	if username == emptyString || password == emptyString {
		return nil, ka.errorf(ErrUsernamePasswordRequired)
	}
	clientID := ka.config.ClientID
	if ka.config.PublicClientID != emptyString {
		clientID = ka.config.PublicClientID
	}
	if clientID == emptyString {
		return nil, ka.errorf(ErrClientIDRequired)
	}

	tokenURL := buildTokenURL(ka.config.URL, ka.config.Realm, ka.config.TokenEndpoint)
	params := TokenRequestParams{
		GrantType: "password",
		ClientID:  clientID,
		Username:  username,
		Password:  password,
		Scopes:    scopes,
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

func (ka *KeycloakClient) ExchangeCodeForToken(ctx context.Context, code, redirectURI string) (*oauth2.Token, error) {
	if code == emptyString || redirectURI == emptyString {
		return nil, ka.errorf(ErrUsernamePasswordRequired)
	}

	tokenURL := buildTokenURL(ka.config.URL, ka.config.Realm, ka.config.TokenEndpoint)
	params := TokenRequestParams{
		GrantType:   "authorization_code",
		ClientID:    ka.config.ClientID,
		Code:        code,
		RedirectURI: redirectURI,
	}
	if ka.config.ClientSecret != "" {
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

func (ka *KeycloakClient) StartDeviceLogin(ctx context.Context, scopes []string) (*DeviceAuthResponse, error) {
	clientID := ka.config.ClientID
	if clientID == "" {
		return nil, ka.errorf(ErrClientIDRequired)
	}

	deviceURL := ka.config.URL + "/realms/" + ka.config.Realm + "/protocol/openid-connect/auth/device"

	data := url.Values{}
	data.Set("client_id", clientID)
	if ka.config.ClientSecret != "" {
		data.Set("client_secret", ka.config.ClientSecret)
	}
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	body, statusCode, err := makeFormRequest(ctx, ka.client, deviceURL, data, ka.language)
	if err != nil {
		return nil, err
	}

	if statusCode != http.StatusOK {
		return nil, ka.errorf(ErrFailedToObtainLoginToken, statusCode, string(body))
	}

	var deviceResp DeviceAuthResponse
	if err := json.Unmarshal(body, &deviceResp); err != nil {
		return nil, ka.errorf(ErrFailedToParseToken, err)
	}

	return &deviceResp, nil
}

func (ka *KeycloakClient) PollDeviceToken(ctx context.Context, deviceCode string, interval int) (*oauth2.Token, error) {
	clientID := ka.config.ClientID
	if clientID == "" {
		return nil, ka.errorf(ErrClientIDRequired)
	}

	tokenURL := buildTokenURL(ka.config.URL, ka.config.Realm, "")

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			params := TokenRequestParams{
				GrantType:  "urn:ietf:params:oauth:grant-type:device_code",
				DeviceCode: deviceCode,
				ClientID:   clientID,
			}
			if ka.config.ClientSecret != "" {
				params.ClientSecret = ka.config.ClientSecret
			}

			body, statusCode, err := requestTokenWithStatus(ctx, ka.client, tokenURL, params, ka.language)
			if err != nil {
				return nil, err
			}

			if statusCode == http.StatusOK {
				var token oauth2.Token
				if err := json.Unmarshal(body, &token); err != nil {
					return nil, ka.errorf(ErrFailedToParseToken, err)
				}
				if token.AccessToken == "" {
					return nil, ka.errorf(ErrNoAccessToken)
				}
				return &token, nil
			}

			var errResp map[string]string
			json.Unmarshal(body, &errResp) //nolint:errcheck // best-effort: error response body may not be JSON
			if errResp["error"] == "authorization_pending" || errResp["error"] == "slow_down" {
				if errResp["error"] == "slow_down" {
					interval += 5
					ticker.Reset(time.Duration(interval) * time.Second)
				}
				continue
			}
			return nil, ka.errorf(ErrFailedToObtainLoginToken, statusCode, string(body))
		}
	}
}

func (ka *KeycloakClient) GetTokenForRealm(ctx context.Context, realm, clientID, clientSecret string) (*oauth2.Token, error) {
	if realm == emptyString {
		return nil, ka.errorf(ErrKeycloakRealmRequired)
	}

	if clientID == emptyString {
		clientID = ka.config.ClientID
	}
	if clientSecret == emptyString {
		clientSecret = ka.config.ClientSecret
	}

	if clientID == emptyString || clientSecret == emptyString {
		return nil, ka.errorf(ErrClientIDAndSecretRequired)
	}

	tokenURL := buildTokenURL(ka.config.URL, realm, "")
	params := TokenRequestParams{
		GrantType:    "client_credentials",
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}

	return requestTokenWithOAuth2Response(ctx, ka.client, tokenURL, params, ka.language)
}

func (ka *KeycloakClient) LoginUserInRealm(ctx context.Context, realm, username, password string, clientID string, scopes []string) (*oauth2.Token, error) {
	if realm == emptyString {
		return nil, ka.errorf(ErrKeycloakRealmRequired)
	}
	if username == emptyString || password == emptyString {
		return nil, ka.errorf(ErrUsernamePasswordRequired)
	}

	if clientID == emptyString {
		return nil, ka.errorf(ErrClientIDRequired)
	}

	tokenURL := buildTokenURL(ka.config.URL, realm, "")
	params := TokenRequestParams{
		GrantType: "password",
		ClientID:  clientID,
		Username:  username,
		Password:  password,
		Scopes:    scopes,
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
