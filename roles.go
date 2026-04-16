package keycloaklib

import (
	"context"
	"fmt"
	"net/http"
)

// CreateRole creates a new realm-level role.
func (ka *KeycloakClient) CreateRole(ctx context.Context, role *Role) error {
	path := fmt.Sprintf("/admin/realms/%s/roles", ka.config.Realm)
	return ka.doRequest(ctx, http.MethodPost, path, role, nil)
}

// GetRoles returns all realm-level roles.
func (ka *KeycloakClient) GetRoles(ctx context.Context) ([]Role, error) {
	path := fmt.Sprintf("/admin/realms/%s/roles", ka.config.Realm)
	var roles []Role
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &roles)
	return roles, err
}

// GetRoleByID returns the realm-level role with the given internal ID.
func (ka *KeycloakClient) GetRoleByID(ctx context.Context, roleID string) (*Role, error) {
	if roleID == emptyString {
		return nil, ka.errorf(ErrUsernameRequired)
	}

	path := fmt.Sprintf("/admin/realms/%s/roles-by-id/%s", ka.config.Realm, roleID)
	var role Role
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &role)
	return &role, err
}
