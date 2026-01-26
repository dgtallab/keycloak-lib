package keycloaklib

import (
	"bytes"
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

func makeFormRequest(ctx context.Context, httpClient *http.Client, url string, data url.Values, lang string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(data.Encode()))
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

	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	} else if config.HTTPClient.Timeout == 0 {
		config.HTTPClient.Timeout = 30 * time.Second
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

	ka.mu.RLock()
	accessToken := ka.accessToken
	ka.mu.RUnlock()

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := ka.client.Do(req)
	if err != nil {
		return ka.errorf(ErrFailedToExecuteRequest, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		bodyBytes, _ := io.ReadAll(resp.Body)

		if refreshErr := ka.ensureTokenValid(ctx); refreshErr != nil {
			return ka.errorf(ErrRequestFailed, resp.StatusCode, string(bodyBytes))
		}

		if body != nil {
			jsonBody, err := json.Marshal(body)
			if err != nil {
				return ka.errorf(ErrFailedToMarshal, err)
			}
			reqBody = bytes.NewReader(jsonBody)
		}

		req, err = http.NewRequestWithContext(ctx, method, fullURL, reqBody)
		if err != nil {
			return ka.errorf(ErrFailedToCreateRequest, err)
		}

		ka.mu.RLock()
		accessToken = ka.accessToken
		ka.mu.RUnlock()

		req.Header.Set("Authorization", "Bearer "+accessToken)
		req.Header.Set("Content-Type", "application/json")

		resp, err = ka.client.Do(req)
		if err != nil {
			return ka.errorf(ErrFailedToExecuteRequest, err)
		}
		defer resp.Body.Close()
	}

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
	if err := ctx.Err(); err != nil {
		return "", err
	}

	userID, err := ka.CreateUser(ctx, params)
	if err != nil {
		return "", err
	}

	if err := ctx.Err(); err != nil {
		_ = ka.DeleteUser(context.Background(), userID)
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

func (ka *KeycloakClient) ExecuteActionsEmail(ctx context.Context, userID string, actions []string, lifespanSeconds int, redirectURI, clientID string) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	if len(actions) == 0 {
		return ka.errorf(ErrFailedToMarshal)
	}

	basePath := fmt.Sprintf("/admin/realms/%s/users/%s/execute-actions-email", ka.config.Realm, userID)
	q := url.Values{}
	if lifespanSeconds > 0 {
		q.Set("lifespan", fmt.Sprintf("%d", lifespanSeconds))
	}
	if redirectURI != emptyString {
		q.Set("redirect_uri", redirectURI)
	}
	if clientID != emptyString {
		q.Set("client_id", clientID)
	}
	path := basePath
	if encoded := q.Encode(); encoded != "" {
		path = path + "?" + encoded
	}

	return ka.doRequest(ctx, http.MethodPut, path, actions, nil)
}

func (ka *KeycloakClient) SendEmail(ctx context.Context, userID string, actions []string) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}

	if len(actions) == 0 {
		path := fmt.Sprintf("/admin/realms/%s/users/%s/send-verification-email", ka.config.Realm, userID)

		err := ka.doRequest(ctx, http.MethodPut, path, nil, nil)
		if err == nil {
			return nil
		}

		return ka.sendExecuteActionsEmail(ctx, userID, []string{})
	}

	return ka.sendExecuteActionsEmail(ctx, userID, actions)
}

func (ka *KeycloakClient) sendExecuteActionsEmail(ctx context.Context, userID string, actions []string) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/execute-actions-email", ka.config.Realm, userID)
	return ka.doRequest(ctx, http.MethodPut, path, actions, nil)
}

func (ka *KeycloakClient) GetUserByID(ctx context.Context, userID string) (*User, error) {
	path := fmt.Sprintf("/admin/realms/%s/users/%s", ka.config.Realm, userID)
	var user User
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &user)
	return &user, err
}

func (ka *KeycloakClient) GetUserClientRoles(ctx context.Context, userID, clientID string) ([]Role, error) {
	if userID == emptyString {
		return nil, ka.errorf(ErrUserIDRequired)
	}
	if clientID == emptyString {
		return nil, ka.errorf(ErrClientIDRequired)
	}

	client, err := ka.getClientByClientID(ctx, clientID)
	if err != nil {
		return nil, ka.errorf(ErrFailedToGetClientWrapper, err)
	}
	clientUUID := client.ID

	path := fmt.Sprintf("/admin/realms/%s/users/%s/role-mappings/clients/%s", ka.config.Realm, userID, clientUUID)
	var roles []Role
	err = ka.doRequest(ctx, http.MethodGet, path, nil, &roles)
	return roles, err
}

func (ka *KeycloakClient) GetUserRealmRoles(ctx context.Context, userID string) ([]Role, error) {
	if userID == emptyString {
		return nil, ka.errorf(ErrUserIDRequired)
	}

	path := fmt.Sprintf("/admin/realms/%s/users/%s/role-mappings/realm", ka.config.Realm, userID)
	var roles []Role
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &roles)
	return roles, err
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

func (ka *KeycloakClient) getClientByClientID(ctx context.Context, clientID string) (*Client, error) {
	if cached, ok := ka.clientCache.Load(clientID); ok {
		return cached.(*Client), nil
	}

	path := fmt.Sprintf("/admin/realms/%s/clients?clientId=%s", ka.config.Realm, url.QueryEscape(clientID))
	var clients []Client
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &clients)
	if err != nil {
		return nil, err
	}
	if len(clients) == 0 {
		return nil, ka.errorf(ErrNoClientFound, clientID)
	}

	client := &clients[0]
	ka.clientCache.Store(clientID, client)
	return client, nil
}

func (ka *KeycloakClient) getClientRole(ctx context.Context, clientUUID, roleName string) (*Role, error) {
	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles/%s", ka.config.Realm, clientUUID, url.PathEscape(roleName))
	var role Role
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &role)
	return &role, err
}

func (ka *KeycloakClient) AddClientRolesToUser(ctx context.Context, userID, clientID string, roleNames []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	client, err := ka.getClientByClientID(ctx, clientID)
	if err != nil {
		return ka.errorf(ErrFailedToGetClientWrapper, err)
	}
	clientUUID := client.ID

	var roles []Role
	for _, roleName := range roleNames {
		if err := ctx.Err(); err != nil {
			return err
		}

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

func (ka *KeycloakClient) GetUsersByAttribute(ctx context.Context, attributeKey, attributeValue string) ([]User, error) {
	if attributeKey == emptyString {
		return nil, ka.errorf(ErrUsernameRequired)
	}

	query := fmt.Sprintf("%s:%s", attributeKey, attributeValue)
	path := fmt.Sprintf("/admin/realms/%s/users?q=%s", ka.config.Realm, url.QueryEscape(query))

	var users []User
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &users)
	return users, err
}

func (ka *KeycloakClient) GetUsersByAttributes(ctx context.Context, attributes map[string]string) ([]User, error) {
	if len(attributes) == 0 {
		return ka.GetUsers(ctx, "")
	}

	queries := make([]string, 0, len(attributes))
	for key, value := range attributes {
		query := fmt.Sprintf("%s:%s", key, value)
		queries = append(queries, "q="+url.QueryEscape(query))
	}

	path := fmt.Sprintf("/admin/realms/%s/users?%s", ka.config.Realm, strings.Join(queries, "&"))

	var users []User
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &users)
	return users, err
}

func (ka *KeycloakClient) GetUsersWithParams(ctx context.Context, params UserSearchParams) ([]User, error) {
	queryParams := url.Values{}

	if params.Search != "" {
		queryParams.Set("search", params.Search)
	}
	if params.Email != "" {
		queryParams.Set("email", params.Email)
	}
	if params.Username != "" {
		queryParams.Set("username", params.Username)
	}
	if params.FirstName != "" {
		queryParams.Set("firstName", params.FirstName)
	}
	if params.LastName != "" {
		queryParams.Set("lastName", params.LastName)
	}
	if params.Enabled != nil {
		queryParams.Set("enabled", fmt.Sprintf("%t", *params.Enabled))
	}
	if params.EmailVerified != nil {
		queryParams.Set("emailVerified", fmt.Sprintf("%t", *params.EmailVerified))
	}
	if params.First > 0 {
		queryParams.Set("first", fmt.Sprintf("%d", params.First))
	}
	if params.Max > 0 {
		queryParams.Set("max", fmt.Sprintf("%d", params.Max))
	}
	if params.Exact {
		queryParams.Set("exact", "true")
	}
	if params.BriefRepresentation {
		queryParams.Set("briefRepresentation", "true")
	}

	for key, value := range params.Attributes {
		query := fmt.Sprintf("%s:%s", key, value)
		queryParams.Add("q", query)
	}

	path := fmt.Sprintf("/admin/realms/%s/users", ka.config.Realm)
	if len(queryParams) > 0 {
		path += "?" + queryParams.Encode()
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
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	if groupID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	path := fmt.Sprintf("/admin/realms/%s/users/%s/groups/%s", ka.config.Realm, userID, groupID)
	return ka.doRequest(ctx, http.MethodPut, path, nil, nil)
}

func (ka *KeycloakClient) RemoveUserFromGroup(ctx context.Context, userID, groupID string) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	if groupID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	path := fmt.Sprintf("/admin/realms/%s/users/%s/groups/%s", ka.config.Realm, userID, groupID)
	return ka.doRequest(ctx, http.MethodDelete, path, nil, nil)
}

func (ka *KeycloakClient) AddRealmRolesToGroup(ctx context.Context, groupID string, roleNames []string) error {
	if groupID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	if len(roleNames) == 0 {
		return ka.errorf(ErrUsernameRequired)
	}

	var roles []Role
	for _, roleName := range roleNames {
		if err := ctx.Err(); err != nil {
			return err
		}

		path := fmt.Sprintf("/admin/realms/%s/roles/%s", ka.config.Realm, url.PathEscape(roleName))
		var role Role
		err := ka.doRequest(ctx, http.MethodGet, path, nil, &role)
		if err != nil {
			return ka.errorf(ErrFailedToGetClientRoleWrapper, roleName, err)
		}
		roles = append(roles, role)
	}

	path := fmt.Sprintf("/admin/realms/%s/groups/%s/role-mappings/realm", ka.config.Realm, groupID)
	return ka.doRequest(ctx, http.MethodPost, path, roles, nil)
}

func (ka *KeycloakClient) AddClientRolesToGroup(ctx context.Context, groupID, clientID string, roleNames []string) error {
	if groupID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	if clientID == emptyString {
		return ka.errorf(ErrClientIDRequired)
	}
	if len(roleNames) == 0 {
		return ka.errorf(ErrUsernameRequired)
	}

	client, err := ka.getClientByClientID(ctx, clientID)
	if err != nil {
		return ka.errorf(ErrFailedToGetClientWrapper, err)
	}
	clientUUID := client.ID

	var roles []Role
	for _, roleName := range roleNames {
		if err := ctx.Err(); err != nil {
			return err
		}

		role, err := ka.getClientRole(ctx, clientUUID, roleName)
		if err != nil {
			return ka.errorf(ErrFailedToGetClientRoleWrapper, roleName, err)
		}
		roles = append(roles, *role)
	}

	path := fmt.Sprintf("/admin/realms/%s/groups/%s/role-mappings/clients/%s", ka.config.Realm, groupID, clientUUID)
	return ka.doRequest(ctx, http.MethodPost, path, roles, nil)
}

func (ka *KeycloakClient) CreateGroupWithRoles(ctx context.Context, groupName string, realmRoles []string, clientRoles map[string][]string) (string, error) {
	if groupName == emptyString {
		return emptyString, ka.errorf(ErrUsernameRequired)
	}

	group := &Group{
		Name: groupName,
	}

	if err := ka.CreateGroup(ctx, group); err != nil {
		return emptyString, err
	}

	createdGroup, err := ka.GetGroupByName(ctx, groupName)
	if err != nil {
		return emptyString, ka.errorf(ErrFailedToGetClientWrapper, err)
	}

	if len(realmRoles) > 0 {
		if err := ka.AddRealmRolesToGroup(ctx, createdGroup.ID, realmRoles); err != nil {
			_ = ka.DeleteGroup(ctx, createdGroup.ID)
			return emptyString, ka.errorf(ErrFailedToAddRolesUserDeleted, err)
		}
	}

	for clientID, roles := range clientRoles {
		if err := ctx.Err(); err != nil {
			_ = ka.DeleteGroup(ctx, createdGroup.ID)
			return emptyString, err
		}

		if len(roles) > 0 {
			if err := ka.AddClientRolesToGroup(ctx, createdGroup.ID, clientID, roles); err != nil {
				_ = ka.DeleteGroup(ctx, createdGroup.ID)
				return emptyString, ka.errorf(ErrFailedToAddRolesUserDeleted, err)
			}
		}
	}

	return createdGroup.ID, nil
}

func (ka *KeycloakClient) GetGroupByName(ctx context.Context, groupName string) (*Group, error) {
	if groupName == emptyString {
		return nil, ka.errorf(ErrUsernameRequired)
	}

	path := fmt.Sprintf("/admin/realms/%s/groups?search=%s", ka.config.Realm, url.QueryEscape(groupName))
	var groups []Group
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &groups)
	if err != nil {
		return nil, err
	}

	for _, group := range groups {
		if group.Name == groupName {
			return &group, nil
		}
	}

	return nil, ka.errorf(ErrNoUserFound, groupName)
}

func (ka *KeycloakClient) DeleteGroup(ctx context.Context, groupID string) error {
	if groupID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	path := fmt.Sprintf("/admin/realms/%s/groups/%s", ka.config.Realm, groupID)
	return ka.doRequest(ctx, http.MethodDelete, path, nil, nil)
}

func (ka *KeycloakClient) CreateGroupWithUsersAndRoles(ctx context.Context, groupName string, userIDs []string, realmRoles []string, clientRoles map[string][]string) (string, error) {
	if groupName == emptyString {
		return emptyString, ka.errorf(ErrUsernameRequired)
	}

	groupID, err := ka.CreateGroupWithRoles(ctx, groupName, realmRoles, clientRoles)
	if err != nil {
		return emptyString, err
	}

	for _, userID := range userIDs {
		if err := ctx.Err(); err != nil {
			return groupID, err
		}

		if err := ka.AddUserToGroup(ctx, userID, groupID); err != nil {
			return groupID, ka.errorf(ErrFailedToAddRolesUserDeleted, err)
		}
	}

	return groupID, nil
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

func (ka *KeycloakClient) CreateClientRole(ctx context.Context, clientID string, role *Role) (string, error) {
	if clientID == emptyString {
		return emptyString, ka.errorf(ErrClientIDRequired)
	}
	if role == nil || role.Name == emptyString {
		return emptyString, ka.errorf(ErrUsernameRequired)
	}

	client, err := ka.getClientByClientID(ctx, clientID)
	if err != nil {
		return emptyString, ka.errorf(ErrFailedToGetClientWrapper, err)
	}
	clientUUID := client.ID

	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles", ka.config.Realm, clientUUID)
	var createdRole Role
	if err := ka.doRequest(ctx, http.MethodPost, path, role, &createdRole); err != nil {
		return emptyString, err
	}

	if createdRole.ID == emptyString {
		return emptyString, ka.errorf(ErrRequestFailed, "role created but no ID returned")
	}

	return createdRole.ID, nil
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
			json.Unmarshal(body, &errResp)
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

func (ka *KeycloakClient) ClearClientCache() {
	ka.clientCache.Range(func(key, value interface{}) bool {
		ka.clientCache.Delete(key)
		return true
	})
}

func (ka *KeycloakClient) ClearClientCacheByID(clientID string) {
	ka.clientCache.Delete(clientID)
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

func (ka *KeycloakClient) GetAllGroups(ctx context.Context) ([]Group, error) {
	path := fmt.Sprintf("/admin/realms/%s/groups", ka.config.Realm)
	var groups []Group
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &groups)
	return groups, err
}

func (ka *KeycloakClient) GetGroupRoles(ctx context.Context, groupID string) ([]Role, error) {
	if groupID == emptyString {
		return nil, ka.errorf(ErrUserIDRequired)
	}

	path := fmt.Sprintf("/admin/realms/%s/groups/%s/role-mappings/realm", ka.config.Realm, groupID)
	var roles []Role
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &roles)
	return roles, err
}

func (ka *KeycloakClient) GetGroupClientRoles(ctx context.Context, groupID, clientID string) ([]Role, error) {
	if groupID == emptyString {
		return nil, ka.errorf(ErrUserIDRequired)
	}
	if clientID == emptyString {
		return nil, ka.errorf(ErrClientIDRequired)
	}

	client, err := ka.getClientByClientID(ctx, clientID)
	if err != nil {
		return nil, ka.errorf(ErrFailedToGetClientWrapper, err)
	}
	clientUUID := client.ID

	path := fmt.Sprintf("/admin/realms/%s/groups/%s/role-mappings/clients/%s", ka.config.Realm, groupID, clientUUID)
	var roles []Role
	err = ka.doRequest(ctx, http.MethodGet, path, nil, &roles)
	return roles, err
}

func (ka *KeycloakClient) CheckRoleExistsInGroups(ctx context.Context, roleName string) (bool, []Group, error) {
	if roleName == emptyString {
		return false, nil, ka.errorf(ErrUsernameRequired)
	}

	allGroups, err := ka.GetAllGroups(ctx)
	if err != nil {
		return false, nil, err
	}

	var groupsWithRole []Group
	for _, group := range allGroups {
		realmRoles, err := ka.GetGroupRoles(ctx, group.ID)
		if err != nil {
			continue
		}

		for _, role := range realmRoles {
			if role.Name == roleName {
				groupsWithRole = append(groupsWithRole, group)
				break
			}
		}

		clients, err := ka.GetClients(ctx)
		if err != nil {
			continue
		}

		for _, client := range clients {
			clientRoles, err := ka.GetGroupClientRoles(ctx, group.ID, client.ClientID)
			if err != nil {
				continue
			}

			for _, role := range clientRoles {
				if role.Name == roleName {
					found := false
					for _, existingGroup := range groupsWithRole {
						if existingGroup.ID == group.ID {
							found = true
							break
						}
					}
					if !found {
						groupsWithRole = append(groupsWithRole, group)
					}
					break
				}
			}
		}
	}

	return len(groupsWithRole) > 0, groupsWithRole, nil
}

func (ka *KeycloakClient) CheckRoleInSpecificGroup(ctx context.Context, groupID, roleName string) (bool, error) {
	if groupID == emptyString {
		return false, ka.errorf(ErrUserIDRequired)
	}
	if roleName == emptyString {
		return false, ka.errorf(ErrUsernameRequired)
	}

	realmRoles, err := ka.GetGroupRoles(ctx, groupID)
	if err != nil {
		return false, err
	}

	for _, role := range realmRoles {
		if role.Name == roleName {
			return true, nil
		}
	}

	clients, err := ka.GetClients(ctx)
	if err != nil {
		return false, err
	}

	for _, client := range clients {
		clientRoles, err := ka.GetGroupClientRoles(ctx, groupID, client.ClientID)
		if err != nil {
			continue
		}

		for _, role := range clientRoles {
			if role.Name == roleName {
				return true, nil
			}
		}
	}

	return false, nil
}

func (ka *KeycloakClient) UpdateUserData(ctx context.Context, userID string, params UserUpdateParams) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}

	currentUser, err := ka.GetUserByID(ctx, userID)
	if err != nil {
		return ka.errorf(ErrFailedToGetUserWrapper, err)
	}

	if params.Username != emptyString {
		currentUser.Username = params.Username
	}
	if params.Email != emptyString {
		currentUser.Email = params.Email
	}
	if params.FirstName != emptyString {
		currentUser.FirstName = params.FirstName
	}
	if params.LastName != emptyString {
		currentUser.LastName = params.LastName
	}
	if params.Enabled != nil {
		currentUser.Enabled = *params.Enabled
	}
	if params.EmailVerified != nil {
		currentUser.EmailVerified = *params.EmailVerified
	}
	if params.Attributes != nil {
		currentUser.Attributes = params.Attributes
	}

	path := fmt.Sprintf("/admin/realms/%s/users/%s", ka.config.Realm, userID)
	return ka.doRequest(ctx, http.MethodPut, path, currentUser, nil)
}

func (ka *KeycloakClient) UpdateUserPassword(ctx context.Context, userID, newPassword string, temporary bool) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	if newPassword == emptyString {
		return ka.errorf(ErrPasswordRequired)
	}

	credential := Credential{
		Type:      "password",
		Value:     newPassword,
		Temporary: temporary,
	}

	path := fmt.Sprintf("/admin/realms/%s/users/%s/reset-password", ka.config.Realm, userID)
	return ka.doRequest(ctx, http.MethodPut, path, credential, nil)
}

func (ka *KeycloakClient) UpdateUserEmail(ctx context.Context, userID, newEmail string) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	if newEmail == emptyString {
		return ka.errorf(ErrEmailRequired)
	}

	params := UserUpdateParams{
		Email: newEmail,
	}
	return ka.UpdateUserData(ctx, userID, params)
}

func (ka *KeycloakClient) UpdateUserUsername(ctx context.Context, userID, newUsername string) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	if newUsername == emptyString {
		return ka.errorf(ErrUsernameRequired)
	}

	params := UserUpdateParams{
		Username: newUsername,
	}
	return ka.UpdateUserData(ctx, userID, params)
}

func (ka *KeycloakClient) UpdateUserPasswordWithValidation(ctx context.Context, userID, currentPassword, newPassword string, temporary bool) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	if currentPassword == emptyString {
		return ka.errorf(ErrPasswordRequired)
	}
	if newPassword == emptyString {
		return ka.errorf(ErrPasswordRequired)
	}

	user, err := ka.GetUserByID(ctx, userID)
	if err != nil {
		return ka.errorf(ErrFailedToGetUserWrapper, err)
	}

	if user.Username == emptyString {
		return ka.errorf(ErrUsernameRequired)
	}

	err = ka.validateCurrentPassword(ctx, user.Username, currentPassword)
	if err != nil {
		return ka.errorf(ErrFailedToValidateCurrentPassword, err)
	}

	return ka.UpdateUserPassword(ctx, userID, newPassword, temporary)
}

func (ka *KeycloakClient) validateCurrentPassword(ctx context.Context, username, password string) error {
	tempClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	clientID := ka.config.ClientID
	if ka.config.PublicClientID != emptyString {
		clientID = ka.config.PublicClientID
	}
	if clientID == emptyString {
		return ka.errorf(ErrClientIDRequired)
	}

	tokenURL := buildTokenURL(ka.config.URL, ka.config.Realm, ka.config.TokenEndpoint)
	params := TokenRequestParams{
		GrantType: "password",
		ClientID:  clientID,
		Username:  username,
		Password:  password,
	}

	if ka.config.ClientSecret != emptyString && ka.config.PublicClientID == emptyString {
		params.ClientSecret = ka.config.ClientSecret
	}

	body, statusCode, err := requestTokenWithStatus(ctx, tempClient, tokenURL, params, ka.language)
	if err != nil {
		return err
	}

	if statusCode != http.StatusOK {
		return ka.errorf(ErrCurrentPasswordIncorrect)
	}

	var token oauth2.Token
	if err := json.Unmarshal(body, &token); err != nil {
		return ka.errorf(ErrFailedToParseToken, err)
	}

	if token.AccessToken == emptyString {
		return ka.errorf(ErrCurrentPasswordIncorrect)
	}

	return nil
}

func (ka *KeycloakClient) GetGroupsWithRole(ctx context.Context, roleName string) ([]Group, error) {
	if roleName == emptyString {
		return nil, ka.errorf(ErrUsernameRequired)
	}

	exists, groups, err := ka.CheckRoleExistsInGroups(ctx, roleName)
	if err != nil {
		return nil, err
	}

	if !exists {
		return []Group{}, nil
	}

	return groups, nil
}

func (ka *KeycloakClient) GetUserGroups(ctx context.Context, userID string) ([]Group, error) {
	if userID == emptyString {
		return nil, ka.errorf(ErrUserIDRequired)
	}

	path := fmt.Sprintf("/admin/realms/%s/users/%s/groups", ka.config.Realm, userID)
	var groups []Group
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &groups)
	return groups, err
}

func (ka *KeycloakClient) GetUserGroupRoles(ctx context.Context, userID string) (map[string][]Role, error) {
	if userID == emptyString {
		return nil, ka.errorf(ErrUserIDRequired)
	}

	userGroups, err := ka.GetUserGroups(ctx, userID)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]Role)

	for _, group := range userGroups {
		realmRoles, err := ka.GetGroupRoles(ctx, group.ID)
		if err != nil {
			continue
		}

		clients, err := ka.GetClients(ctx)
		if err != nil {
			continue
		}

		var allRoles []Role
		allRoles = append(allRoles, realmRoles...)

		for _, client := range clients {
			clientRoles, err := ka.GetGroupClientRoles(ctx, group.ID, client.ClientID)
			if err != nil {
				continue
			}
			allRoles = append(allRoles, clientRoles...)
		}

		if len(allRoles) > 0 {
			result[group.Name] = allRoles
		}
	}

	return result, nil
}

func (ka *KeycloakClient) CheckUserHasRoleInGroups(ctx context.Context, userID, roleName string) (bool, error) {
	if userID == emptyString || roleName == emptyString {
		return false, ka.errorf(ErrUserIDRequired)
	}

	userGroups, err := ka.GetUserGroups(ctx, userID)
	if err != nil {
		return false, err
	}

	for _, group := range userGroups {
		realmRoles, err := ka.GetGroupRoles(ctx, group.ID)
		if err != nil {
			continue
		}

		for _, role := range realmRoles {
			if role.Name == roleName {
				return true, nil
			}
		}
	}

	return false, nil
}

func (ka *KeycloakClient) AddRealmRolesToUser(ctx context.Context, userID string, roleNames []string) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}

	if len(roleNames) == 0 {
		return ka.errorf(ErrUsernameRequired)
	}

	var roles []Role
	for _, roleName := range roleNames {
		if err := ctx.Err(); err != nil {
			return err
		}

		path := fmt.Sprintf("/admin/realms/%s/roles/%s", ka.config.Realm, url.PathEscape(roleName))
		var role Role
		err := ka.doRequest(ctx, http.MethodGet, path, nil, &role)
		if err != nil {
			return ka.errorf(ErrFailedToGetClientRoleWrapper, roleName, err)
		}

		roles = append(roles, role)
	}

	path := fmt.Sprintf("/admin/realms/%s/users/%s/role-mappings/realm", ka.config.Realm, userID)
	return ka.doRequest(ctx, http.MethodPost, path, roles, nil)
}

func (ka *KeycloakClient) RemoveRealmRolesFromUser(ctx context.Context, userID string, roleNames []string) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}

	if len(roleNames) == 0 {
		return ka.errorf(ErrUsernameRequired)
	}

	var roles []Role
	for _, roleName := range roleNames {
		if err := ctx.Err(); err != nil {
			return err
		}

		path := fmt.Sprintf("/admin/realms/%s/roles/%s", ka.config.Realm, url.PathEscape(roleName))
		var role Role
		err := ka.doRequest(ctx, http.MethodGet, path, nil, &role)
		if err != nil {
			return ka.errorf(ErrFailedToGetClientRoleWrapper, roleName, err)
		}

		roles = append(roles, role)
	}

	path := fmt.Sprintf("/admin/realms/%s/users/%s/role-mappings/realm", ka.config.Realm, userID)
	return ka.doRequest(ctx, http.MethodDelete, path, roles, nil)
}

func (ka *KeycloakClient) RemoveClientRolesFromUser(ctx context.Context, userID, clientID string, roleNames []string) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}

	if clientID == emptyString {
		return ka.errorf(ErrClientIDRequired)
	}

	if len(roleNames) == 0 {
		return ka.errorf(ErrUsernameRequired)
	}

	client, err := ka.getClientByClientID(ctx, clientID)
	if err != nil {
		return ka.errorf(ErrFailedToGetClientWrapper, err)
	}

	clientUUID := client.ID

	var roles []Role
	for _, roleName := range roleNames {
		if err := ctx.Err(); err != nil {
			return err
		}

		role, err := ka.getClientRole(ctx, clientUUID, roleName)
		if err != nil {
			return ka.errorf(ErrFailedToGetClientRoleWrapper, roleName, err)
		}

		roles = append(roles, *role)
	}

	path := fmt.Sprintf("/admin/realms/%s/users/%s/role-mappings/clients/%s", ka.config.Realm, userID, clientUUID)
	return ka.doRequest(ctx, http.MethodDelete, path, roles, nil)
}

func (ka *KeycloakClient) AddUserAttribute(ctx context.Context, userID, key string, values []string) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}

	if key == emptyString {
		return ka.errorf(ErrUsernameRequired)
	}

	user, err := ka.GetUserByID(ctx, userID)
	if err != nil {
		return ka.errorf(ErrFailedToGetUserWrapper, err)
	}

	if user.Attributes == nil {
		user.Attributes = make(map[string][]string)
	}

	user.Attributes[key] = values

	params := UserUpdateParams{
		Attributes: user.Attributes,
	}

	return ka.UpdateUserData(ctx, userID, params)
}

func (ka *KeycloakClient) RemoveUserAttribute(ctx context.Context, userID, key string) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}

	if key == emptyString {
		return ka.errorf(ErrUsernameRequired)
	}

	user, err := ka.GetUserByID(ctx, userID)
	if err != nil {
		return ka.errorf(ErrFailedToGetUserWrapper, err)
	}

	if user.Attributes == nil {
		return nil
	}

	delete(user.Attributes, key)

	params := UserUpdateParams{
		Attributes: user.Attributes,
	}

	return ka.UpdateUserData(ctx, userID, params)
}

func (ka *KeycloakClient) UpdateUserAttribute(ctx context.Context, userID, key string, valuesToAdd []string) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}

	if key == emptyString {
		return ka.errorf(ErrUsernameRequired)
	}

	user, err := ka.GetUserByID(ctx, userID)
	if err != nil {
		return ka.errorf(ErrFailedToGetUserWrapper, err)
	}

	if user.Attributes == nil {
		user.Attributes = make(map[string][]string)
	}

	currentValues := user.Attributes[key]

	valueMap := make(map[string]bool)
	for _, v := range currentValues {
		valueMap[v] = true
	}

	for _, v := range valuesToAdd {
		if !valueMap[v] {
			currentValues = append(currentValues, v)
			valueMap[v] = true
		}
	}

	user.Attributes[key] = currentValues

	params := UserUpdateParams{
		Attributes: user.Attributes,
	}

	return ka.UpdateUserData(ctx, userID, params)
}

func (ka *KeycloakClient) RemoveUserAttributeValues(ctx context.Context, userID, key string, valuesToRemove []string) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}

	if key == emptyString {
		return ka.errorf(ErrUsernameRequired)
	}

	user, err := ka.GetUserByID(ctx, userID)
	if err != nil {
		return ka.errorf(ErrFailedToGetUserWrapper, err)
	}

	if user.Attributes == nil || len(user.Attributes[key]) == 0 {
		return nil
	}

	removeMap := make(map[string]bool)
	for _, v := range valuesToRemove {
		removeMap[v] = true
	}

	var newValues []string
	for _, v := range user.Attributes[key] {
		if !removeMap[v] {
			newValues = append(newValues, v)
		}
	}

	if len(newValues) > 0 {
		user.Attributes[key] = newValues
	} else {
		delete(user.Attributes, key)
	}

	params := UserUpdateParams{
		Attributes: user.Attributes,
	}

	return ka.UpdateUserData(ctx, userID, params)
}

func (ka *KeycloakClient) GetUserAttribute(ctx context.Context, userID, key string) ([]string, error) {
	if userID == emptyString {
		return nil, ka.errorf(ErrUserIDRequired)
	}

	if key == emptyString {
		return nil, ka.errorf(ErrUsernameRequired)
	}

	user, err := ka.GetUserByID(ctx, userID)
	if err != nil {
		return nil, ka.errorf(ErrFailedToGetUserWrapper, err)
	}

	if user.Attributes == nil {
		return []string{}, nil
	}

	return user.Attributes[key], nil
}

func (ka *KeycloakClient) RemoveRealmRolesFromGroup(ctx context.Context, groupID string, roleNames []string) error {
	if groupID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}

	if len(roleNames) == 0 {
		return ka.errorf(ErrUsernameRequired)
	}

	var roles []Role
	for _, roleName := range roleNames {
		if err := ctx.Err(); err != nil {
			return err
		}

		path := fmt.Sprintf("/admin/realms/%s/roles/%s", ka.config.Realm, url.PathEscape(roleName))
		var role Role
		err := ka.doRequest(ctx, http.MethodGet, path, nil, &role)
		if err != nil {
			return ka.errorf(ErrFailedToGetClientRoleWrapper, roleName, err)
		}

		roles = append(roles, role)
	}

	path := fmt.Sprintf("/admin/realms/%s/groups/%s/role-mappings/realm", ka.config.Realm, groupID)
	return ka.doRequest(ctx, http.MethodDelete, path, roles, nil)
}

func (ka *KeycloakClient) RemoveClientRolesFromGroup(ctx context.Context, groupID, clientID string, roleNames []string) error {
	if groupID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}

	if clientID == emptyString {
		return ka.errorf(ErrClientIDRequired)
	}

	if len(roleNames) == 0 {
		return ka.errorf(ErrUsernameRequired)
	}

	client, err := ka.getClientByClientID(ctx, clientID)
	if err != nil {
		return ka.errorf(ErrFailedToGetClientWrapper, err)
	}

	clientUUID := client.ID

	var roles []Role
	for _, roleName := range roleNames {
		if err := ctx.Err(); err != nil {
			return err
		}

		role, err := ka.getClientRole(ctx, clientUUID, roleName)
		if err != nil {
			return ka.errorf(ErrFailedToGetClientRoleWrapper, roleName, err)
		}

		roles = append(roles, *role)
	}

	path := fmt.Sprintf("/admin/realms/%s/groups/%s/role-mappings/clients/%s", ka.config.Realm, groupID, clientUUID)
	return ka.doRequest(ctx, http.MethodDelete, path, roles, nil)
}

func (ka *KeycloakClient) CreateUserWithAttributes(ctx context.Context, params UserCreateParams, realmRoles []string, clientID string, clientRoles []string) (string, error) {
	if err := ctx.Err(); err != nil {
		return emptyString, err
	}

	userID, err := ka.CreateUser(ctx, params)
	if err != nil {
		return emptyString, err
	}

	if len(realmRoles) > 0 {
		if err := ctx.Err(); err != nil {
			_ = ka.DeleteUser(context.Background(), userID)
			return emptyString, err
		}

		err = ka.AddRealmRolesToUser(ctx, userID, realmRoles)
		if err != nil {
			delErr := ka.DeleteUser(ctx, userID)
			if delErr != nil {
				return emptyString, ka.errorf(ErrFailedToAddRolesRollbackFailed, err, delErr)
			}
			return emptyString, ka.errorf(ErrFailedToAddRolesUserDeleted, err)
		}
	}

	if clientID != emptyString && len(clientRoles) > 0 {
		if err := ctx.Err(); err != nil {
			_ = ka.DeleteUser(context.Background(), userID)
			return emptyString, err
		}

		err = ka.AddClientRolesToUser(ctx, userID, clientID, clientRoles)
		if err != nil {
			delErr := ka.DeleteUser(ctx, userID)
			if delErr != nil {
				return emptyString, ka.errorf(ErrFailedToAddRolesRollbackFailed, err, delErr)
			}
			return emptyString, ka.errorf(ErrFailedToAddRolesUserDeleted, err)
		}
	}

	return userID, nil
}
