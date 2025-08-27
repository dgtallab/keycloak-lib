package keycloaklib

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func getClientToken(ctx context.Context, config *Config, lang string) (*tokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", config.URL, config.Realm)
	if config.TokenEndpoint != "" {
		tokenURL = config.TokenEndpoint
	}
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", config.ClientID)
	data.Set("client_secret", config.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, makeError(lang, ErrFailedToCreateRequest, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := config.HTTPClient.Do(req)
	if err != nil {
		return nil, makeError(lang, ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, makeError(lang, ErrFailedToReadResponse, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, makeError(lang, ErrFailedToGetToken, resp.StatusCode, body)
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

func (ka *KeycloakClient) refreshAdminToken(ctx context.Context) error {
	if ka.refreshToken == emptyString {
		return ka.errorf(ErrNoRefreshToken)
	}

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", ka.config.URL, ka.config.Realm)
	if ka.config.TokenEndpoint != "" {
		tokenURL = ka.config.TokenEndpoint
	}
	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", ka.config.ClientID)
	data.Set("client_secret", ka.config.ClientSecret)
	data.Set("refresh_token", ka.refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return ka.errorf(ErrFailedToCreateRequest, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ka.client.Do(req)
	if err != nil {
		return ka.errorf(ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ka.errorf(ErrFailedToReadResponse, err)
	}
	if resp.StatusCode != http.StatusOK {
		return ka.errorf(ErrFailedToRefreshToken, resp.StatusCode, body)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return ka.errorf(ErrFailedToParseToken, err)
	}
	if tok.AccessToken == emptyString {
		return ka.errorf(ErrNoAccessTokenInRefresh)
	}

	ka.accessToken = tok.AccessToken
	ka.refreshToken = tok.RefreshToken
	ka.expiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Add(-30 * time.Second)
	return nil
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

	if err := ka.refreshAdminToken(ctx); err == nil {
		return nil
	}

	tok, err := getClientToken(ctx, ka.config, ka.language)
	if err != nil {
		return ka.errorf(ErrTokenRefreshFailed, err)
	}
	ka.accessToken = tok.AccessToken
	ka.refreshToken = tok.RefreshToken
	ka.expiry = time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Add(-30 * time.Second)
	return nil
}

func NewKeycloakClient(ctx context.Context, config *Config) (*KeycloakClient, error) {
	if config == nil {
		return nil, makeError(EN, ErrConfigRequired)
	}
	lang := config.Language
	if lang != PT {
		lang = EN
	}

	if config.ClientID == emptyString || config.ClientSecret == emptyString {
		return nil, makeError(lang, ErrClientIDAndSecretRequired)
	}

	tok, err := getClientToken(ctx, config, lang)
	if err != nil {
		return nil, err
	}

	expiry := time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second).Add(-30 * time.Second)

	ka := &KeycloakClient{
		client:       config.HTTPClient,
		accessToken:  tok.AccessToken,
		refreshToken: tok.RefreshToken,
		expiry:       expiry,
		config:       config,
		language:     lang,
		baseURL:      fmt.Sprintf("%s/admin/realms/%s/users", config.URL, config.Realm),
	}
	return ka, nil
}

func (ka *KeycloakClient) doRequest(ctx context.Context, method, path string, body interface{}, result interface{}) error {
	if err := ka.ensureTokenValid(ctx); err != nil {
		return err
	}

	fullURL := ka.config.URL + path

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return ka.errorf(ErrFailedToMarshal, err)
		}
		reqBody = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, reqBody)
	if err != nil {
		return ka.errorf(ErrFailedToCreateRequest, err)
	}
	req.Header.Set("Authorization", "Bearer "+ka.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ka.client.Do(req)
	if err != nil {
		return ka.errorf(ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return ka.errorf(ErrRequestFailed, resp.StatusCode, string(bodyBytes))
	}

	if result != nil {
		return json.NewDecoder(resp.Body).Decode(result)
	}
	return nil
}

func (ka *KeycloakClient) CreateUser(ctx context.Context, params UserCreateParams) (string, error) {
	user := User{
		Username:        params.Username,
		Email:           params.Email,
		FirstName:       params.FirstName,
		LastName:        params.LastName,
		Enabled:         params.Enabled,
		EmailVerified:   params.EmailVerified,
		Attributes:      params.Attributes,
		RequiredActions: params.RequiredActions,
		Credentials:     params.Credentials,
	}

	path := fmt.Sprintf("/admin/realms/%s/users", ka.config.Realm)
	if err := ka.doRequest(ctx, http.MethodPost, path, user, nil); err != nil {
		return emptyString, err
	}

	return ka.GetUserIDByUsername(ctx, params.Username, true)
}

func (ka *KeycloakClient) CreateUserWithRoles(ctx context.Context, params UserCreateParams, clientID string, roleNames []string) (string, error) {
	userID, err := ka.CreateUser(ctx, params)
	if err != nil {
		return "", err
	}

	err = ka.AddClientRolesToUser(ctx, userID, clientID, roleNames)
	if err != nil {
		delErr := ka.DeleteUser(ctx, userID)
		if delErr != nil {
			return "", ka.errorf(ErrFailedToAddRolesRollbackFailed, err, delErr)
		}
		return "", ka.errorf(ErrFailedToAddRolesUserDeleted, err)
	}

	return userID, nil
}

func (ka *KeycloakClient) GetUserByID(ctx context.Context, userID string) (*User, error) {
	path := fmt.Sprintf("/admin/realms/%s/users/%s", ka.config.Realm, userID)
	var user User
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &user)
	return &user, err
}

func (ka *KeycloakClient) DeleteUser(ctx context.Context, userID string) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s", ka.config.Realm, userID)
	return ka.doRequest(ctx, http.MethodDelete, path, nil, nil)
}

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

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", ka.config.URL, ka.config.Realm)
	if ka.config.TokenEndpoint != "" {
		tokenURL = ka.config.TokenEndpoint
	}

	data := url.Values{}
	data.Set("grant_type", "password")
	data.Set("client_id", clientID)
	if ka.config.ClientSecret != emptyString && ka.config.PublicClientID == emptyString {
		data.Set("client_secret", ka.config.ClientSecret)
	}
	data.Set("username", username)
	data.Set("password", password)
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, ka.errorf(ErrFailedToCreateRequest, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ka.client.Do(req)
	if err != nil {
		return nil, ka.errorf(ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ka.errorf(ErrFailedToReadResponse, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, ka.errorf(ErrFailedToObtainLoginToken, resp.StatusCode, string(body))
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

func (ka *KeycloakClient) getClientByClientID(ctx context.Context, clientID string) (*Client, error) {
	path := fmt.Sprintf("/admin/realms/%s/clients?clientId=%s", ka.config.Realm, url.QueryEscape(clientID))
	var clients []Client
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &clients)
	if err != nil {
		return nil, err
	}
	if len(clients) == 0 {
		return nil, ka.errorf(ErrNoClientFound, clientID)
	}
	return &clients[0], nil
}

func (ka *KeycloakClient) getClientRole(ctx context.Context, clientUUID, roleName string) (*Role, error) {
	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles/%s", ka.config.Realm, clientUUID, url.PathEscape(roleName))
	var role Role
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &role)
	return &role, err
}

func (ka *KeycloakClient) AddClientRolesToUser(ctx context.Context, userID, clientID string, roleNames []string) error {
	client, err := ka.getClientByClientID(ctx, clientID)
	if err != nil {
		return ka.errorf(ErrFailedToGetClientWrapper, err)
	}
	clientUUID := client.ID

	var roles []Role
	for _, roleName := range roleNames {
		role, err := ka.getClientRole(ctx, clientUUID, roleName)
		if err != nil {
			return ka.errorf(ErrFailedToGetClientRoleWrapper, roleName, err)
		}
		roles = append(roles, *role)
	}

	path := fmt.Sprintf("/admin/realms/%s/users/%s/role-mappings/clients/%s", ka.config.Realm, userID, clientUUID)
	return ka.doRequest(ctx, http.MethodPost, path, roles, nil)
}

func (ka *KeycloakClient) TriggerPasswordResetEmail(ctx context.Context, userID string) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	path := fmt.Sprintf("/admin/realms/%s/users/%s/reset-password-email", ka.config.Realm, userID)
	return ka.doRequest(ctx, http.MethodPut, path, nil, nil)
}

func (ka *KeycloakClient) GetUserIDByUsername(ctx context.Context, username string, exact bool) (string, error) {
	if username == emptyString {
		return emptyString, ka.errorf(ErrUsernameRequired)
	}
	path := fmt.Sprintf("/admin/realms/%s/users?username=%s", ka.config.Realm, url.QueryEscape(username))
	if exact {
		path += "&exact=true"
	}
	var users []User
	if err := ka.doRequest(ctx, http.MethodGet, path, nil, &users); err != nil {
		return emptyString, err
	}
	if len(users) == 0 {
		return emptyString, ka.errorf(ErrNoUserFound, username)
	}
	if len(users) > 1 {
		return emptyString, ka.errorf(ErrMultipleUsersFound, username)
	}
	return users[0].ID, nil
}

func (ka *KeycloakClient) UpdateUser(ctx context.Context, userID string, user *User) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s", ka.config.Realm, userID)
	return ka.doRequest(ctx, http.MethodPut, path, user, nil)
}

func (ka *KeycloakClient) GetUsers(ctx context.Context, searchQuery string) ([]User, error) {
	path := fmt.Sprintf("/admin/realms/%s/users", ka.config.Realm)
	if searchQuery != "" {
		path += "?search=" + url.QueryEscape(searchQuery)
	}
	var users []User
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &users)
	return users, err
}

func (ka *KeycloakClient) CreateGroup(ctx context.Context, group *Group) error {
	path := fmt.Sprintf("/admin/realms/%s/groups", ka.config.Realm)
	return ka.doRequest(ctx, http.MethodPost, path, group, nil)
}

func (ka *KeycloakClient) GetGroupByID(ctx context.Context, groupID string) (*Group, error) {
	path := fmt.Sprintf("/admin/realms/%s/groups/%s", ka.config.Realm, groupID)
	var group Group
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &group)
	return &group, err
}

func (ka *KeycloakClient) AddUserToGroup(ctx context.Context, userID, groupID string) error {
	path := fmt.Sprintf("/admin/realms/%s/groups/%s/members/%s", ka.config.Realm, groupID, userID)
	return ka.doRequest(ctx, http.MethodPut, path, nil, nil)
}

func (ka *KeycloakClient) CreateRole(ctx context.Context, role *Role) error {
	path := fmt.Sprintf("/admin/realms/%s/roles", ka.config.Realm)
	return ka.doRequest(ctx, http.MethodPost, path, role, nil)
}

func (ka *KeycloakClient) GetRoles(ctx context.Context) ([]Role, error) {
	path := fmt.Sprintf("/admin/realms/%s/roles", ka.config.Realm)
	var roles []Role
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &roles)
	return roles, err
}

func (ka *KeycloakClient) CreateClient(ctx context.Context, client *Client) error {
	path := fmt.Sprintf("/admin/realms/%s/clients", ka.config.Realm)
	return ka.doRequest(ctx, http.MethodPost, path, client, nil)
}

func (ka *KeycloakClient) GetClientRoles(ctx context.Context, clientID string) ([]Role, error) {
	client, err := ka.getClientByClientID(ctx, clientID)
	if err != nil {
		return nil, ka.errorf(ErrFailedToGetClientWrapper, err)
	}
	clientUUID := client.ID

	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles", ka.config.Realm, clientUUID)
	var roles []Role
	err = ka.doRequest(ctx, http.MethodGet, path, nil, &roles)
	return roles, err
}

func (ka *KeycloakClient) GetClients(ctx context.Context) ([]Client, error) {
	path := fmt.Sprintf("/admin/realms/%s/clients", ka.config.Realm)
	var clients []Client
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &clients)
	return clients, err
}

func (ka *KeycloakClient) LogoutUser(ctx context.Context, userID string) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/logout", ka.config.Realm, userID)
	return ka.doRequest(ctx, http.MethodPost, path, nil, nil)
}

func (ka *KeycloakClient) GetSessions(ctx context.Context, userID string) ([]map[string]interface{}, error) {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/sessions", ka.config.Realm, userID)
	var sessions []map[string]interface{}
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &sessions)
	return sessions, err
}

func (ka *KeycloakClient) StartDeviceLogin(ctx context.Context, scopes []string) (*DeviceAuthResponse, error) {
	clientID := ka.config.ClientID
	if clientID == "" {
		return nil, ka.errorf(ErrClientIDRequired)
	}

	deviceURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/auth/device", ka.config.URL, ka.config.Realm)

	data := url.Values{}
	data.Set("client_id", clientID)
	if ka.config.ClientSecret != "" {
		data.Set("client_secret", ka.config.ClientSecret)
	}
	if len(scopes) > 0 {
		data.Set("scope", strings.Join(scopes, " "))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deviceURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, ka.errorf(ErrFailedToCreateRequest, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ka.client.Do(req)
	if err != nil {
		return nil, ka.errorf(ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ka.errorf(ErrFailedToReadResponse, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, ka.errorf(ErrFailedToObtainLoginToken, resp.StatusCode, string(body))
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

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", ka.config.URL, ka.config.Realm)

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			data := url.Values{}
			data.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
			data.Set("device_code", deviceCode)
			data.Set("client_id", clientID)
			if ka.config.ClientSecret != "" {
				data.Set("client_secret", ka.config.ClientSecret)
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
			if err != nil {
				return nil, ka.errorf(ErrFailedToCreateRequest, err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := ka.client.Do(req)
			if err != nil {
				return nil, ka.errorf(ErrFailedToExecuteRequest, err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return nil, ka.errorf(ErrFailedToReadResponse, err)
			}

			if resp.StatusCode == http.StatusOK {
				var token oauth2.Token
				if err := json.Unmarshal(body, &token); err != nil {
					return nil, ka.errorf(ErrFailedToParseToken, err)
				}
				if token.AccessToken == "" {
					return nil, ka.errorf(ErrNoAccessToken)
				}
				return &token, nil
			} else {
				var errResp map[string]string
				json.Unmarshal(body, &errResp)
				if errResp["error"] == "authorization_pending" || errResp["error"] == "slow_down" {
					if errResp["error"] == "slow_down" {
						interval += 5
						ticker.Reset(time.Duration(interval) * time.Second)
					}
					continue
				}
				return nil, ka.errorf(ErrFailedToObtainLoginToken, resp.StatusCode, string(body))
			}
		}
	}
}

func (ka *KeycloakClient) ExchangeCodeForToken(ctx context.Context, code, redirectURI string) (*oauth2.Token, error) {
	if code == emptyString || redirectURI == emptyString {
		return nil, ka.errorf(ErrUsernameRequired)
	}

	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", ka.config.URL, ka.config.Realm)
	if ka.config.TokenEndpoint != "" {
		tokenURL = ka.config.TokenEndpoint
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", ka.config.ClientID)
	if ka.config.ClientSecret != "" {
		data.Set("client_secret", ka.config.ClientSecret)
	}
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, ka.errorf(ErrFailedToCreateRequest, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := ka.client.Do(req)
	if err != nil {
		return nil, ka.errorf(ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ka.errorf(ErrFailedToReadResponse, err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, ka.errorf(ErrFailedToObtainLoginToken, resp.StatusCode, string(bodyBytes))
	}

	var token oauth2.Token
	if err := json.Unmarshal(bodyBytes, &token); err != nil {
		return nil, ka.errorf(ErrFailedToParseToken, err)
	}

	if token.AccessToken == emptyString {
		return nil, ka.errorf(ErrNoAccessToken)
	}

	return &token, nil
}

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
