package keycloaklib

import (
	"context"
	"encoding/json"
	"net/http"
)

type ContextKey string

const (
	TokenClaimsKey ContextKey = "keycloak_token_claims"
	RawTokenKey    ContextKey = "keycloak_raw_token"
)

type AuthMiddleware struct {
	verifier      *KeycloakVerifier
	errorHandler  func(w http.ResponseWriter, r *http.Request, err error)
	optional      bool
	requiredRoles []string
	clientID      string
}

type AuthMiddlewareConfig struct {
	Verifier      *KeycloakVerifier
	ErrorHandler  func(w http.ResponseWriter, r *http.Request, err error)
	Optional      bool
	RequiredRoles []string
	ClientID      string
}

func NewAuthMiddleware(config AuthMiddlewareConfig) *AuthMiddleware {
	middleware := &AuthMiddleware{
		verifier:      config.Verifier,
		errorHandler:  config.ErrorHandler,
		optional:      config.Optional,
		requiredRoles: config.RequiredRoles,
		clientID:      config.ClientID,
	}

	if middleware.errorHandler == nil {
		middleware.errorHandler = defaultErrorHandler
	}

	return middleware
}

func (am *AuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == emptyString {
			if am.optional {
				next.ServeHTTP(w, r)
				return
			}
			am.errorHandler(w, r, NewAuthError("missing authorization header", http.StatusUnauthorized))
			return
		}

		token, err := ExtractTokenFromHeader(authHeader)
		if err != nil {
			am.errorHandler(w, r, NewAuthError("invalid authorization header", http.StatusUnauthorized))
			return
		}

		claims, err := am.verifier.ValidateAccessToken(r.Context(), token)
		if err != nil {
			am.errorHandler(w, r, NewAuthError("invalid or expired token", http.StatusUnauthorized))
			return
		}

		if len(am.requiredRoles) > 0 {
			hasRole := false
			for _, role := range am.requiredRoles {
				if claims.HasRealmRole(role) {
					hasRole = true
					break
				}
				if am.clientID != emptyString && claims.HasClientRole(am.clientID, role) {
					hasRole = true
					break
				}
			}
			if !hasRole {
				am.errorHandler(w, r, NewAuthError("insufficient permissions", http.StatusForbidden))
				return
			}
		}

		ctx := context.WithValue(r.Context(), TokenClaimsKey, claims)
		ctx = context.WithValue(ctx, RawTokenKey, token)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (am *AuthMiddleware) HandlerFunc(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		am.Handler(next).ServeHTTP(w, r)
	}
}

type AuthError struct {
	Message    string
	StatusCode int
}

func (e *AuthError) Error() string {
	return e.Message
}

func NewAuthError(message string, statusCode int) *AuthError {
	return &AuthError{
		Message:    message,
		StatusCode: statusCode,
	}
}

func defaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	statusCode := http.StatusUnauthorized
	if authErr, ok := err.(*AuthError); ok {
		statusCode = authErr.StatusCode
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   "authentication_failed",
		"message": err.Error(),
	})
}

func GetTokenClaims(r *http.Request) (*TokenClaims, bool) {
	claims, ok := r.Context().Value(TokenClaimsKey).(*TokenClaims)
	return claims, ok
}

func GetRawToken(r *http.Request) (string, bool) {
	token, ok := r.Context().Value(RawTokenKey).(string)
	return token, ok
}

func RequireRole(verifier *KeycloakVerifier, role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		middleware := NewAuthMiddleware(AuthMiddlewareConfig{
			Verifier:      verifier,
			RequiredRoles: []string{role},
		})
		return middleware.Handler(next)
	}
}

func RequireClientRole(verifier *KeycloakVerifier, clientID, role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		middleware := NewAuthMiddleware(AuthMiddlewareConfig{
			Verifier:      verifier,
			ClientID:      clientID,
			RequiredRoles: []string{role},
		})
		return middleware.Handler(next)
	}
}

func RequireAuthentication(verifier *KeycloakVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		middleware := NewAuthMiddleware(AuthMiddlewareConfig{
			Verifier: verifier,
		})
		return middleware.Handler(next)
	}
}

func OptionalAuthentication(verifier *KeycloakVerifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		middleware := NewAuthMiddleware(AuthMiddlewareConfig{
			Verifier: verifier,
			Optional: true,
		})
		return middleware.Handler(next)
	}
}
