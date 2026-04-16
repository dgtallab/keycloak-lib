package keycloaklib

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// NewKeycloakClient creates a new admin client authenticated via client_credentials.
// The client automatically refreshes its token when it expires.
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

// doRequest executes an authenticated Admin REST API request.
// On 401 it refreshes the token once and retries transparently.
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
