package keycloaklib

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// getClientByClientID fetches the internal Keycloak client representation by its clientId string.
// Results are cached in clientCache to avoid repeated Admin API calls within the same session.
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

// getClientRole fetches a single role from a client by its UUID and role name.
func (ka *KeycloakClient) getClientRole(ctx context.Context, clientUUID, roleName string) (*Role, error) {
	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles/%s", ka.config.Realm, clientUUID, url.PathEscape(roleName))
	var role Role
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &role)
	return &role, err
}

// ClearClientCache removes all entries from the in-memory client UUID cache.
func (ka *KeycloakClient) ClearClientCache() {
	ka.clientCache.Range(func(key, value interface{}) bool {
		ka.clientCache.Delete(key)
		return true
	})
}

// ClearClientCacheByID removes a single clientID entry from the in-memory cache.
func (ka *KeycloakClient) ClearClientCacheByID(clientID string) {
	ka.clientCache.Delete(clientID)
}

// CreateClient registers a new OAuth2 client in the realm.
func (ka *KeycloakClient) CreateClient(ctx context.Context, client *Client) error {
	path := fmt.Sprintf("/admin/realms/%s/clients", ka.config.Realm)
	return ka.doRequest(ctx, http.MethodPost, path, client, nil)
}

// GetClients returns all clients registered in the realm.
func (ka *KeycloakClient) GetClients(ctx context.Context) ([]Client, error) {
	path := fmt.Sprintf("/admin/realms/%s/clients", ka.config.Realm)
	var clients []Client
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &clients)
	return clients, err
}

// GetClientRoles returns all roles defined for the given client.
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

// CreateClientRole creates a new role in the given client and returns its ID.
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
	if err := ka.doRequest(ctx, http.MethodPost, path, role, nil); err != nil {
		return emptyString, err
	}

	roles, err := ka.GetClientRoles(ctx, clientID)
	if err != nil {
		return emptyString, err
	}
	for _, r := range roles {
		if r.Name == role.Name {
			return r.ID, nil
		}
	}
	return emptyString, ka.errorf(ErrRequestFailed, "role criada mas ID não encontrado")
}

// UpdateClientRole updates an existing client role by its name.
func (ka *KeycloakClient) UpdateClientRole(ctx context.Context, clientID, roleName string, role *Role) error {
	if clientID == emptyString {
		return ka.errorf(ErrClientIDRequired)
	}
	if roleName == emptyString || role == nil {
		return ka.errorf(ErrUsernameRequired)
	}

	client, err := ka.getClientByClientID(ctx, clientID)
	if err != nil {
		return ka.errorf(ErrFailedToGetClientWrapper, err)
	}
	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles/%s", ka.config.Realm, client.ID, url.PathEscape(roleName))
	return ka.doRequest(ctx, http.MethodPut, path, role, nil)
}

// DeleteClientRole removes a role from the given client.
func (ka *KeycloakClient) DeleteClientRole(ctx context.Context, clientID, roleName string) error {
	if clientID == emptyString {
		return ka.errorf(ErrClientIDRequired)
	}
	if roleName == emptyString {
		return ka.errorf(ErrUsernameRequired)
	}

	client, err := ka.getClientByClientID(ctx, clientID)
	if err != nil {
		return ka.errorf(ErrFailedToGetClientWrapper, err)
	}

	path := fmt.Sprintf("/admin/realms/%s/clients/%s/roles/%s", ka.config.Realm, client.ID, url.PathEscape(roleName))
	return ka.doRequest(ctx, http.MethodDelete, path, nil, nil)
}
