package keycloaklib

import "context"

// AddUserAttribute sets the given attribute key to the provided values for a user.
// If the key already exists its values are replaced.
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

// RemoveUserAttribute deletes the given attribute key from a user. No-op if the key does not exist.
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

// UpdateUserAttribute merges valuesToAdd into the existing values for key, ignoring duplicates.
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

	valueMap := make(map[string]bool, len(currentValues))
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

// RemoveUserAttributeValues removes specific values from an attribute key.
// If no values remain the key is deleted entirely.
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

	removeMap := make(map[string]bool, len(valuesToRemove))
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

// GetUserAttribute returns the values for the given attribute key.
// Returns an empty slice if the attribute does not exist.
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
