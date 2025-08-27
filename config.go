package keycloaklib

import (
	"crypto/tls"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	URL               string
	Realm             string
	ClientID          string
	ClientSecret      string
	PublicClientID    string
	Language          string
	HTTPClient        *http.Client
	TokenEndpoint     string
	AllowInsecureHTTP bool
}

type ConfigBuilder struct {
	config Config
}

func NewConfigBuilder() *ConfigBuilder {
	return &ConfigBuilder{
		config: Config{
			Language:   DefaultLanguage,
			HTTPClient: &http.Client{Timeout: 30 * time.Second},
		},
	}
}

func (b *ConfigBuilder) WithLanguage(language string) *ConfigBuilder {
	if language == PT {
		b.config.Language = PT
	} else {
		b.config.Language = DefaultLanguage
	}
	return b
}

func (b *ConfigBuilder) WithURL(url string) *ConfigBuilder {
	b.config.URL = url
	return b
}

func (b *ConfigBuilder) WithRealm(realm string) *ConfigBuilder {
	b.config.Realm = realm
	return b
}

func (b *ConfigBuilder) WithClientID(clientID string) *ConfigBuilder {
	b.config.ClientID = clientID
	return b
}

func (b *ConfigBuilder) WithClientSecret(clientSecret string) *ConfigBuilder {
	b.config.ClientSecret = clientSecret
	return b
}

func (b *ConfigBuilder) WithPublicClientID(publicClientID string) *ConfigBuilder {
	b.config.PublicClientID = publicClientID
	return b
}

func (b *ConfigBuilder) WithHTTPClient(client *http.Client) *ConfigBuilder {
	b.config.HTTPClient = client
	return b
}

func (b *ConfigBuilder) WithCustomTLS(tlsConfig *tls.Config) *ConfigBuilder {
	b.config.HTTPClient.Transport = &http.Transport{TLSClientConfig: tlsConfig}
	return b
}

func (b *ConfigBuilder) WithTokenEndpoint(endpoint string) *ConfigBuilder {
	b.config.TokenEndpoint = endpoint
	return b
}

func (b *ConfigBuilder) WithAllowInsecureHTTP(allow bool) *ConfigBuilder {
	b.config.AllowInsecureHTTP = allow
	return b
}

func (b *ConfigBuilder) Build() (*Config, error) {
	lang := b.config.Language
	if lang != PT {
		lang = DefaultLanguage
	}

	if b.config.URL == emptyString {
		msg := translations[lang][ErrKeycloakURLRequired]
		return nil, errors.New(msg)
	}
	if !strings.HasPrefix(b.config.URL, "https://") && !b.config.AllowInsecureHTTP {
		msg := translations[lang][ErrKeycloakURLMustUseHTTPS]
		return nil, errors.New(msg)
	}
	u, err := url.Parse(b.config.URL)
	if err != nil || u.Host == "" {
		msg := translations[lang][ErrInvalidKeycloakURL]
		return nil, errors.New(msg)
	}
	if b.config.Realm == emptyString {
		msg := translations[lang][ErrKeycloakRealmRequired]
		return nil, errors.New(msg)
	}
	if b.config.ClientID == emptyString {
		msg := translations[lang][ErrKeycloakClientIDRequired]
		return nil, errors.New(msg)
	}
	if b.config.ClientSecret == emptyString {
		msg := translations[lang][ErrKeycloakClientSecretRequired]
		return nil, errors.New(msg)
	}
	if b.config.HTTPClient == nil {
		b.config.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &b.config, nil
}
