package keycloaklib

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// GetUserRealmRoles returns the realm-level roles assigned to a user.
func (ka *KeycloakClient) GetUserRealmRoles(ctx context.Context, userID string) ([]Role, error) {
	if userID == emptyString {
		return nil, ka.errorf(ErrUserIDRequired)
	}

	path := fmt.Sprintf("/admin/realms/%s/users/%s/role-mappings/realm", ka.config.Realm, userID)
	var roles []Role
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &roles)
	return roles, err
}

// GetUserClientRoles returns the client-level roles assigned to a user for the given clientID.
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

// AddRealmRolesToUser assigns realm-level roles to a user.
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

// AddClientRolesToUser assigns client-level roles to a user.
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

// RemoveRealmRolesFromUser removes realm-level roles from a user.
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

// RemoveClientRolesFromUser removes client-level roles from a user.
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
