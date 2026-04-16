package keycloaklib

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// CreateUser creates a new user in the realm and returns its ID.
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

// CreateUserWithRoles creates a user and assigns client roles atomically.
// If role assignment fails the user is deleted (rollback).
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

// CreateUserWithAttributes creates a user and atomically assigns realm and client roles.
// On failure the user is deleted (rollback).
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

// GetUserByID returns the full user representation for the given ID.
func (ka *KeycloakClient) GetUserByID(ctx context.Context, userID string) (*User, error) {
	path := fmt.Sprintf("/admin/realms/%s/users/%s", ka.config.Realm, userID)
	var user User
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &user)
	return &user, err
}

// GetUserIDByUsername resolves a username to its Keycloak user ID.
// Pass exact=true to require an exact username match.
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

// GetUsers returns all users optionally filtered by a general search query.
func (ka *KeycloakClient) GetUsers(ctx context.Context, searchQuery string) ([]User, error) {
	path := fmt.Sprintf("/admin/realms/%s/users", ka.config.Realm)
	if searchQuery != "" {
		path += "?search=" + url.QueryEscape(searchQuery)
	}
	var users []User
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &users)
	return users, err
}

// GetUsersByAttribute returns users that have the given attribute key/value pair.
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

// GetUsersByAttributes returns users matching all provided attribute key/value pairs.
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

// GetUsersWithParams returns users filtered by the provided search parameters.
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

// GetUsersByRoleID returns all users that have the given client role (by role ID).
func (ka *KeycloakClient) GetUsersByRoleID(ctx context.Context, clientID, roleID string) ([]User, error) {
	if clientID == emptyString {
		return nil, ka.errorf(ErrClientIDRequired)
	}
	if roleID == emptyString {
		return nil, ka.errorf(ErrUsernameRequired)
	}

	client, err := ka.getClientByClientID(ctx, clientID)
	if err != nil {
		return nil, ka.errorf(ErrFailedToGetClientWrapper, err)
	}
	clientUUID := client.ID

	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles/%s/users", ka.config.Realm, clientUUID, roleID)

	var users []User
	err = ka.doRequest(ctx, http.MethodGet, path, nil, &users)
	return users, err
}

// UpdateUser performs a full update of the user resource.
func (ka *KeycloakClient) UpdateUser(ctx context.Context, userID string, user *User) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s", ka.config.Realm, userID)
	return ka.doRequest(ctx, http.MethodPut, path, user, nil)
}

// UpdateUserData applies a partial update to a user using only the non-zero fields of params.
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

// UpdateUserEmail updates only the email address of a user.
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

// UpdateUserUsername updates only the username of a user.
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

// UpdateUserPassword resets a user's password via the admin API (no current password required).
// Set temporary=true to force the user to change the password on next login.
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

// UpdateUserPasswordWithValidation verifies currentPassword before updating to newPassword.
// Returns ErrCurrentPasswordIncorrect if the current password does not match.
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

// validateCurrentPassword attempts a password grant to verify the current password is correct.
// Uses a temporary HTTP client to avoid interfering with the admin session.
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

// DeleteUser permanently removes a user from the realm.
func (ka *KeycloakClient) DeleteUser(ctx context.Context, userID string) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s", ka.config.Realm, userID)
	return ka.doRequest(ctx, http.MethodDelete, path, nil, nil)
}

// ExecuteActionsEmail sends a required-actions email to the user.
// lifespanSeconds controls how long the link is valid (0 uses the realm default).
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

// SendEmail sends a verification or actions email to the user.
// If no actions are provided, a verification email is sent.
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

// TriggerPasswordResetEmail sends a password-reset email to the user.
func (ka *KeycloakClient) TriggerPasswordResetEmail(ctx context.Context, userID string) error {
	if userID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	path := fmt.Sprintf("/admin/realms/%s/users/%s/reset-password-email", ka.config.Realm, userID)
	return ka.doRequest(ctx, http.MethodPut, path, nil, nil)
}

// LogoutUser invalidates all sessions for the given user.
func (ka *KeycloakClient) LogoutUser(ctx context.Context, userID string) error {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/logout", ka.config.Realm, userID)
	return ka.doRequest(ctx, http.MethodPost, path, nil, nil)
}

// GetSessions returns active sessions for the given user.
func (ka *KeycloakClient) GetSessions(ctx context.Context, userID string) ([]map[string]interface{}, error) {
	path := fmt.Sprintf("/admin/realms/%s/users/%s/sessions", ka.config.Realm, userID)
	var sessions []map[string]interface{}
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &sessions)
	return sessions, err
}
