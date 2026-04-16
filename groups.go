package keycloaklib

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
)

// CreateGroup creates a new group in the realm.
func (ka *KeycloakClient) CreateGroup(ctx context.Context, group *Group) error {
	path := fmt.Sprintf("/admin/realms/%s/groups", ka.config.Realm)
	return ka.doRequest(ctx, http.MethodPost, path, group, nil)
}

// GetGroupByID returns the group with the given internal ID.
func (ka *KeycloakClient) GetGroupByID(ctx context.Context, groupID string) (*Group, error) {
	path := fmt.Sprintf("/admin/realms/%s/groups/%s", ka.config.Realm, groupID)
	var group Group
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &group)
	return &group, err
}

// GetGroupByName searches for a group by its exact name.
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

// GetAllGroups returns all groups in the realm.
func (ka *KeycloakClient) GetAllGroups(ctx context.Context) ([]Group, error) {
	path := fmt.Sprintf("/admin/realms/%s/groups", ka.config.Realm)
	var groups []Group
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &groups)
	return groups, err
}

// DeleteGroup removes a group from the realm.
func (ka *KeycloakClient) DeleteGroup(ctx context.Context, groupID string) error {
	if groupID == emptyString {
		return ka.errorf(ErrUserIDRequired)
	}
	path := fmt.Sprintf("/admin/realms/%s/groups/%s", ka.config.Realm, groupID)
	return ka.doRequest(ctx, http.MethodDelete, path, nil, nil)
}

// AddUserToGroup adds a user to a group.
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

// RemoveUserFromGroup removes a user from a group.
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

// GetUserGroups returns all groups the given user belongs to.
func (ka *KeycloakClient) GetUserGroups(ctx context.Context, userID string) ([]Group, error) {
	if userID == emptyString {
		return nil, ka.errorf(ErrUserIDRequired)
	}

	path := fmt.Sprintf("/admin/realms/%s/users/%s/groups", ka.config.Realm, userID)
	var groups []Group
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &groups)
	return groups, err
}

// GetGroupRoles returns the realm-level roles assigned to a group.
func (ka *KeycloakClient) GetGroupRoles(ctx context.Context, groupID string) ([]Role, error) {
	if groupID == emptyString {
		return nil, ka.errorf(ErrUserIDRequired)
	}

	path := fmt.Sprintf("/admin/realms/%s/groups/%s/role-mappings/realm", ka.config.Realm, groupID)
	var roles []Role
	err := ka.doRequest(ctx, http.MethodGet, path, nil, &roles)
	return roles, err
}

// GetGroupClientRoles returns the client-level roles assigned to a group.
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

// AddRealmRolesToGroup assigns realm-level roles to a group.
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

// AddClientRolesToGroup assigns client-level roles to a group.
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

// RemoveRealmRolesFromGroup removes realm-level roles from a group.
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

// RemoveClientRolesFromGroup removes client-level roles from a group.
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

// CreateGroupWithRoles creates a group and assigns realm and client roles to it atomically.
// On failure the group is deleted (rollback).
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

// CreateGroupWithUsersAndRoles creates a group with roles and adds the given users to it.
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

// GetUserGroupRoles returns a map of group name → combined realm+client roles for all groups a user belongs to.
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

// CheckRoleExistsInGroups checks whether any group in the realm has the given role (realm or client).
// Returns a flag and the list of groups that contain the role.
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

// CheckRoleInSpecificGroup checks whether a specific group has the given role (realm or client).
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

// GetGroupsWithRole returns all groups that contain the given role.
// Returns an empty slice if no group has the role.
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

// CheckUserHasRoleInGroups checks whether any group the user belongs to has the given realm role.
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
