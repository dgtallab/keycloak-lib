# Keycloak Go Library

![Go Version](https://img.shields.io/badge/Go-1.23%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen) <!-- Add actual badges if available -->
![GoDoc](https://pkg.go.dev/badge/github.com/dgtallab/keycloak-lib?status.svg)
A lightweight Go library for integrating with Keycloak. It supports Keycloak Admin REST API operations (e.g., user, group, role, and client management) using direct HTTP calls. Built with `net/http` and `encoding/json` for admin interactions, and `golang.org/x/oauth2` for token handling, it focuses on security, thread-safety, performance, and ease of use.

This library is suitable for backend services, APIs, or CLI tools requiring Keycloak integration. It handles token fetching via client credentials grant, automatic refresh using `expires_in`, caching with thread-safety, and supports multiple realms/clients via configurable options.

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Initializing the Library](#initializing-the-library)
  - [Token Verification & Middleware](#token-verification--middleware)
  - [Admin Operations](#admin-operations)
  - [Group Management](#group-management)
  - [Advanced Authentication](#advanced-authentication)
- [Full Example: Web App Integration](#full-example-web-app-integration)
- [Best Practices](#best-practices)
- [Security Considerations](#security-considerations)
- [Testing](#testing)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgments](#acknowledgments)

## Features
- **Admin API Support**: User create/get/update/delete with attributes, passwords, verification, and required actions; add client-specific roles to users; trigger password reset emails; get user ID by username; comprehensive group management with role assignments; role/client management; session handling and logout.
- **Token Management**: Client credentials grant, caching with lazy refresh, expiration checks, and thread-safety using RWMutex to minimize API calls.
- **Token Verification**: OIDC-compliant JWT verification with automatic public key fetching; extract user claims, roles, groups, and custom attributes from tokens.
- **HTTP Middleware**: Ready-to-use middleware for protecting HTTP endpoints with authentication; support for role-based access control; compatible with standard `http.Handler`, Gorilla Mux, Chi, and other popular routers.
- **User Login**: Supports password grant for obtaining OAuth2 tokens with scopes; device code flow; authorization code exchange; magic link generation.
- **Thread-Safety**: RWMutex-protected token operations for concurrent use.
- **Customization**: Builder pattern for config; support for custom HTTP clients, TLS configs, and token endpoints; error messages in English or Portuguese.
- **Minimal Dependencies**: Standard lib + `golang.org/x/oauth2` + `github.com/coreos/go-oidc/v3`; no heavy wrappers.
- **Error Handling**: Custom errors with internationalized messages (en/pt), avoiding sensitive info leaks.
- **Performance Optimizations**: Reused HTTP client with connection pooling and timeouts; context support for cancellations.
- **Security Enhancements**: Enforced HTTPS (with optional override for testing); input validation to prevent injections.
- **Builder Pattern**: Fluent builders for configuration and user creation parameters for improved readability and flexibility.

## Installation
Add to your `go.mod`:

```bash
go get github.com/dgtallab/keycloak-lib@latest
```

Run `go mod tidy`. Requires Go 1.23+.

## Configuration
Use the `ConfigBuilder` to create and validate the configuration in a fluent manner. You can also specify the language for error messages ("en" for English or "pt" for Portuguese; defaults to "en"). For testing, allow insecure HTTP via `WithAllowInsecureHTTP(true)` (not recommended for production).

### Environment Variables (Optional)
While the library doesn't load env vars automatically, you can use them in your app:

- `KEYCLOAK_URL`: Server URL (required).
- `KEYCLOAK_REALM`: Realm (required).
- `KEYCLOAK_CLIENT_ID`: Client ID (required).
- `KEYCLOAK_CLIENT_SECRET`: Secret (required).
- `KEYCLOAK_PUBLIC_CLIENT_ID`: Public Client (optional).
- `KEYCLOAK_LANGUAGE`: Language ("en" or "pt").

### Creating Config
```go
import (
    "os"
    "github.com/dgtallab/keycloak-lib"
    "github.com/joho/godotenv" // Optional for .env loading
)

_ = godotenv.Load()

config, err := keycloaklib.NewConfigBuilder().
    WithURL(os.Getenv("KEYCLOAK_URL")).
    WithRealm(os.Getenv("KEYCLOAK_REALM")).
    WithClientID(os.Getenv("KEYCLOAK_CLIENT_ID")).
    WithClientSecret(os.Getenv("KEYCLOAK_CLIENT_SECRET")).
    WithPublicClientID(os.Getenv("KEYCLOAK_PUBLIC_CLIENT_ID")).
    WithLanguage(os.Getenv("KEYCLOAK_LANGUAGE")). // Optional: "pt" for Portuguese errors
    // WithAllowInsecureHTTP(true) // For testing only (allows HTTP)
    Build()
if err != nil {
    log.Fatal(err)
}
```

## Usage

### Initializing the Library
Init once and reuse for thread-safe operations.

```go
ctx := context.Background()

admin, err := keycloaklib.NewKeycloakClient(ctx, config)
if err != nil {
    log.Fatal(err)
}
```

### Token Verification & Middleware
The library provides powerful token verification and middleware capabilities for protecting your HTTP endpoints.

#### Creating a Token Verifier
```go
verifier, err := keycloaklib.NewKeycloakVerifier(ctx, config)
if err != nil {
    log.Fatal(err)
}
```

#### Validating a Token Manually
```go
// Extract token from Authorization header
token, err := keycloaklib.ExtractTokenFromHeader(r.Header.Get("Authorization"))
if err != nil {
    // Handle error
}

// Validate and extract claims
claims, err := verifier.ValidateAccessToken(ctx, token)
if err != nil {
    // Handle error
}

// Access user information
userID := claims.Sub
email := claims.Email
username := claims.PreferredUsername

// Check roles
if claims.HasRealmRole("admin") {
    // User is admin
}

// Check client-specific roles
if claims.HasClientRole("my-app", "user") {
    // User has 'user' role in 'my-app' client
}

// Check group membership
if claims.IsInGroup("/managers") {
    // User is in managers group
}
```

#### Using the HTTP Middleware
The library provides ready-to-use middleware for protecting your HTTP endpoints:

##### Basic Authentication Middleware
```go
// Create middleware
authMiddleware := keycloaklib.NewAuthMiddleware(keycloaklib.AuthMiddlewareConfig{
    Verifier: verifier,
})

// Protect an endpoint
http.Handle("/api/protected", authMiddleware.Handler(http.HandlerFunc(protectedHandler)))

func protectedHandler(w http.ResponseWriter, r *http.Request) {
    // Get user claims from context
    claims, ok := keycloaklib.GetTokenClaims(r)
    if !ok {
        http.Error(w, "Failed to get claims", http.StatusInternalServerError)
        return
    }
    
    fmt.Fprintf(w, "Hello %s!", claims.Name)
}
```

##### Role-Based Access Control
```go
// Require specific realm role
adminMiddleware := keycloaklib.NewAuthMiddleware(keycloaklib.AuthMiddlewareConfig{
    Verifier:      verifier,
    RequiredRoles: []string{"admin"},
})

http.Handle("/api/admin", adminMiddleware.Handler(http.HandlerFunc(adminHandler)))

// Require client-specific role
userMiddleware := keycloaklib.NewAuthMiddleware(keycloaklib.AuthMiddlewareConfig{
    Verifier:      verifier,
    ClientID:      "my-app",
    RequiredRoles: []string{"user"},
})

http.Handle("/api/user", userMiddleware.Handler(http.HandlerFunc(userHandler)))
```

##### Optional Authentication
```go
// Allow access with or without token (but validate if present)
http.Handle("/api/content", keycloaklib.OptionalAuthentication(verifier)(
    http.HandlerFunc(contentHandler),
))

func contentHandler(w http.ResponseWriter, r *http.Request) {
    claims, authenticated := keycloaklib.GetTokenClaims(r)
    
    if authenticated {
        // Provide personalized content
        fmt.Fprintf(w, "Welcome back, %s!", claims.Name)
    } else {
        // Provide public content
        fmt.Fprintf(w, "Welcome, guest!")
    }
}
```

##### Custom Error Handler
```go
func customErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusUnauthorized)
    json.NewEncoder(w).Encode(map[string]string{
        "error": err.Error(),
    })
}

authMiddleware := keycloaklib.NewAuthMiddleware(keycloaklib.AuthMiddlewareConfig{
    Verifier:     verifier,
    ErrorHandler: customErrorHandler,
})
```

##### Using with Popular Routers

**With Gorilla Mux:**
```go
r := mux.NewRouter()

// Protected routes
api := r.PathPrefix("/api").Subrouter()
api.Use(keycloaklib.RequireAuthentication(verifier))
api.HandleFunc("/profile", profileHandler)

// Admin routes
admin := r.PathPrefix("/admin").Subrouter()
admin.Use(keycloaklib.RequireRole(verifier, "admin"))
admin.HandleFunc("/users", usersHandler)
```

**With Chi Router:**
```go
r := chi.NewRouter()

r.Route("/api", func(r chi.Router) {
    r.Use(keycloaklib.RequireAuthentication(verifier))
    r.Get("/profile", profileHandler)
    
    r.Group(func(r chi.Router) {
        r.Use(keycloaklib.RequireRole(verifier, "admin"))
        r.Get("/admin/users", adminUsersHandler)
    })
})
```

#### Convenience Middleware Functions
```go
// Simple authentication without role checks
RequireAuthentication(verifier)

// Require specific realm role
RequireRole(verifier, "admin")

// Require specific client role
RequireClientRole(verifier, "my-app", "manager")

// Optional authentication (validates if present)
OptionalAuthentication(verifier)
```

For complete examples, see [examples_middleware.go](examples_middleware.go).

### Admin Operations
#### Create User
Use the `UserCreateParamsBuilder` for fluent parameter construction, including optional required actions like "UPDATE_PASSWORD" or "VERIFY_EMAIL".

```go
params, err := keycloaklib.NewUserCreateParamsBuilder().
    WithUsername("username").
    WithEmail("email@example.com").
    WithFirstName("First").
    WithLastName("Last").
    WithAttributes(map[string][]string{"attribute1": {"value1"}}).
    AddCredential(keycloaklib.Credential{Type: "password", Value: "password", Temporary: false}).
    WithRequiredActions([]string{"UPDATE_PASSWORD", "VERIFY_EMAIL"}).
    Build()
if err != nil {
    // Handle error
}
userID, err := admin.CreateUser(ctx, params)
if err != nil {
    // Handle error
}
```

#### Create User with Roles
Creates a user and assigns client-specific roles, with rollback (user deletion) on role assignment failure.

```go
params, err := keycloaklib.NewUserCreateParamsBuilder().
    // ... (same as above)
    Build()
if err != nil {
    // Handle error
}
userID, err := admin.CreateUserWithRoles(ctx, params, "client-id", []string{"role1", "role2"})
if err != nil {
    // Handle error
}
```

#### Get User by ID
```go
user, err := admin.GetUserByID(ctx, "user-id")
if err != nil {
    // Handle error
}
```

#### Update User
```go
updatedUser := &keycloaklib.User{
    FirstName: "NewFirst",
    LastName:  "NewLast",
    // Other fields...
}
err := admin.UpdateUser(ctx, "user-id", updatedUser)
if err != nil {
    // Handle error
}
```

#### Get Users (with Search)
```go
users, err := admin.GetUsers(ctx, "search-query") // Empty string for all users
if err != nil {
    // Handle error
}
```

#### Get User ID by Username
```go
userID, err := admin.GetUserIDByUsername(ctx, "username", true) // true for exact match
if err != nil {
    // Handle error
}
```

#### Delete User
```go
err := admin.DeleteUser(ctx, "user-id")
if err != nil {
    // Handle error
}
```

#### Add Client Roles to User
```go
err := admin.AddClientRolesToUser(ctx, "user-id", "client-id", []string{"role1", "role2"})
if err != nil {
    // Handle error
}
```

#### Trigger Password Reset Email
```go
err := admin.TriggerPasswordResetEmail(ctx, "user-id")
if err != nil {
    // Handle error
}
```

#### Create Group
```go
group := &keycloaklib.Group{Name: "new-group"}
err := admin.CreateGroup(ctx, group)
if err != nil {
    // Handle error
}
```

#### Get Group by ID
```go
group, err := admin.GetGroupByID(ctx, "group-id")
if err != nil {
    // Handle error
}
```

#### Add User to Group
```go
err := admin.AddUserToGroup(ctx, "user-id", "group-id")
if err != nil {
    // Handle error
}
```

#### Create Role
```go
role := &keycloaklib.Role{Name: "new-role"}
err := admin.CreateRole(ctx, role)
if err != nil {
    // Handle error
}
```

#### Get Roles
```go
roles, err := admin.GetRoles(ctx)
if err != nil {
    // Handle error
}
```

#### Get Client Roles
```go
roles, err := admin.GetClientRoles(ctx, "client-id")
if err != nil {
    // Handle error
}
```

#### Create Client
```go
client := &keycloaklib.Client{ClientID: "new-client"}
err := admin.CreateClient(ctx, client)
if err != nil {
    // Handle error
}
```

#### Get Clients
```go
clients, err := admin.GetClients(ctx)
if err != nil {
    // Handle error
}
```

#### Logout User
```go
err := admin.LogoutUser(ctx, "user-id")
if err != nil {
    // Handle error
}
```

#### Get User Sessions
```go
sessions, err := admin.GetSessions(ctx, "user-id")
if err != nil {
    // Handle error
}
```

### Group Management
The library provides comprehensive group management capabilities, including creating groups, assigning roles to groups, and managing user-group associations.

#### Create Group (Basic)
```go
group := &keycloaklib.Group{Name: "Developers"}
err := admin.CreateGroup(ctx, group)
if err != nil {
    // Handle error
}
```

#### Get Group by ID
```go
group, err := admin.GetGroupByID(ctx, "group-id")
if err != nil {
    // Handle error
}
```

#### Get Group by Name
```go
group, err := admin.GetGroupByName(ctx, "Developers")
if err != nil {
    // Handle error
}
fmt.Printf("Group ID: %s, Name: %s\n", group.ID, group.Name)
```

#### Get All Groups
```go
groups, err := admin.GetAllGroups(ctx)
if err != nil {
    // Handle error
}
for _, group := range groups {
    fmt.Printf("Group: %s (ID: %s)\n", group.Name, group.ID)
}
```

#### Delete Group
```go
err := admin.DeleteGroup(ctx, "group-id")
if err != nil {
    // Handle error
}
```

#### Add User to Existing Group
```go
// Option 1: If you have both IDs
err := admin.AddUserToGroup(ctx, "user-id", "group-id")
if err != nil {
    // Handle error
}

// Option 2: Using username and group name
userID, err := admin.GetUserIDByUsername(ctx, "john.doe", true)
if err != nil {
    // Handle error
}
group, err := admin.GetGroupByName(ctx, "Developers")
if err != nil {
    // Handle error
}
err = admin.AddUserToGroup(ctx, userID, group.ID)
if err != nil {
    // Handle error
}
```

#### Add Multiple Users to a Group
```go
groupID := "group-123"
userIDs := []string{"user-001", "user-002", "user-003"}

for _, userID := range userIDs {
    err := admin.AddUserToGroup(ctx, userID, groupID)
    if err != nil {
        log.Printf("Failed to add user %s: %v\n", userID, err)
        continue
    }
    fmt.Printf("User %s added successfully!\n", userID)
}
```

#### Add Realm Roles to Group
Assign realm-level roles to a group. All users in the group will inherit these roles.

```go
err := admin.AddRealmRolesToGroup(ctx, "group-id", []string{"admin", "user"})
if err != nil {
    // Handle error
}
```

#### Add Client Roles to Group
Assign client-specific roles to a group.

```go
err := admin.AddClientRolesToGroup(ctx, "group-id", "my-client-id", []string{"view-users", "manage-users"})
if err != nil {
    // Handle error
}
```

#### Get Group Roles
```go
// Get realm roles
realmRoles, err := admin.GetGroupRoles(ctx, "group-id")
if err != nil {
    // Handle error
}

// Get client-specific roles
clientRoles, err := admin.GetGroupClientRoles(ctx, "group-id", "client-id")
if err != nil {
    // Handle error
}
```

#### Create Group with Roles (Recommended)
Creates a group and assigns roles in a single transaction with automatic rollback on failure.

```go
groupID, err := admin.CreateGroupWithRoles(
    ctx,
    "Administrators",                                    // Group name
    []string{"admin", "super-user"},                    // Realm roles
    map[string][]string{                                // Client roles
        "api-client": {"manage-users", "view-reports"},
        "web-client": {"full-access"},
    },
)
if err != nil {
    // Handle error - group will be rolled back if role assignment fails
}
fmt.Printf("Group created with ID: %s\n", groupID)
```

#### Create Complete Group (Group + Roles + Users)
Creates a group, assigns roles, and adds users in one operation with automatic rollback.

```go
groupID, err := admin.CreateGroupWithUsersAndRoles(
    ctx,
    "Project Managers",                                 // Group name
    []string{"user-id-1", "user-id-2", "user-id-3"},  // User IDs
    []string{"project-manager"},                       // Realm roles
    map[string][]string{                               // Client roles
        "project-api": {"manage-projects", "view-reports"},
        "hr-api": {"view-employees"},
    },
)
if err != nil {
    // Handle error - full rollback on any failure
}
fmt.Printf("Complete group created with ID: %s\n", groupID)
```

#### Get User's Groups
```go
groups, err := admin.GetUserGroups(ctx, "user-id")
if err != nil {
    // Handle error
}
for _, group := range groups {
    fmt.Printf("User is in group: %s\n", group.Name)
}
```

#### Check User Has Role in Groups
Check if a user has a specific role through any of their groups.

```go
hasRole, err := admin.CheckUserHasRoleInGroups(ctx, "user-id", "admin")
if err != nil {
    // Handle error
}
if hasRole {
    fmt.Println("User has admin role through group membership")
}
```

#### Check Role Exists in Groups
Find all groups that have a specific role assigned.

```go
exists, groups, err := admin.CheckRoleExistsInGroups(ctx, "developer")
if err != nil {
    // Handle error
}
if exists {
    fmt.Printf("Role 'developer' found in %d groups\n", len(groups))
    for _, group := range groups {
        fmt.Printf("  - %s\n", group.Name)
    }
}
```

#### Complete Example: Group-Based Access Control
```go
package main

import (
    "context"
    "fmt"
    "log"
    "github.com/dgtallab/keycloak-lib"
)

func setupGroupBasedAccess() {
    ctx := context.Background()
    
    // Initialize client
    config, _ := keycloaklib.NewConfigBuilder().
        WithURL("https://keycloak.example.com").
        WithRealm("my-realm").
        WithClientID("admin-client").
        WithClientSecret("secret").
        Build()
    
    client, err := keycloaklib.NewKeycloakClient(ctx, config)
    if err != nil {
        log.Fatal(err)
    }
    
    // 1. Create developer group with appropriate roles
    devGroupID, err := client.CreateGroupWithRoles(
        ctx,
        "Developers",
        []string{"developer"},
        map[string][]string{
            "api-service": {"read-api", "write-api"},
        },
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("✅ Developer group created: %s\n", devGroupID)
    
    // 2. Create manager group with elevated permissions
    mgrGroupID, err := client.CreateGroupWithRoles(
        ctx,
        "Managers",
        []string{"manager", "developer"},
        map[string][]string{
            "api-service": {"read-api", "write-api", "admin-api"},
            "reports": {"view-all-reports"},
        },
    )
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("✅ Manager group created: %s\n", mgrGroupID)
    
    // 3. Add users to appropriate groups
    users := map[string]string{
        "john.doe":  devGroupID,
        "jane.doe":  devGroupID,
        "bob.smith": mgrGroupID,
    }
    
    for username, groupID := range users {
        userID, err := client.GetUserIDByUsername(ctx, username, true)
        if err != nil {
            log.Printf("❌ User %s not found\n", username)
            continue
        }
        
        err = client.AddUserToGroup(ctx, userID, groupID)
        if err != nil {
            log.Printf("❌ Failed to add %s to group\n", username)
            continue
        }
        fmt.Printf("✅ User %s added to group\n", username)
    }
    
    // 4. Verify group permissions
    groups, err := client.GetAllGroups(ctx)
    if err != nil {
        log.Fatal(err)
    }
    
    for _, group := range groups {
        realmRoles, _ := client.GetGroupRoles(ctx, group.ID)
        fmt.Printf("\n📁 Group: %s\n", group.Name)
        fmt.Printf("   Realm Roles: ")
        for _, role := range realmRoles {
            fmt.Printf("%s ", role.Name)
        }
        fmt.Println()
    }
}
```

#### Best Practices for Group Management

1. **Use Group-Based Roles**: Instead of assigning roles directly to users, assign them to groups for easier management.

2. **Hierarchical Naming**: Use clear naming conventions like "Dev-Backend", "Dev-Frontend", "Admin-SuperUser".

3. **Atomic Operations**: Use `CreateGroupWithRoles` or `CreateGroupWithUsersAndRoles` for atomic operations with automatic rollback.

4. **Regular Audits**: Periodically check group memberships and roles using `GetGroupRoles` and `GetUserGroups`.

5. **Minimize Direct User Roles**: Rely on group inheritance to reduce management complexity.

6. **Document Group Purposes**: Keep track of what each group represents and which permissions it grants.

Example of a complete workflow:
```go
// Define your organizational structure
type OrgStructure struct {
    Groups map[string]GroupConfig
}

type GroupConfig struct {
    Name        string
    RealmRoles  []string
    ClientRoles map[string][]string
    Members     []string
}

func setupOrganization(client *keycloaklib.KeycloakClient) error {
    ctx := context.Background()
    
    structure := OrgStructure{
        Groups: map[string]GroupConfig{
            "engineering": {
                Name:       "Engineering",
                RealmRoles: []string{"developer"},
                ClientRoles: map[string][]string{
                    "api": {"read", "write"},
                },
                Members: []string{"dev1@example.com", "dev2@example.com"},
            },
            "management": {
                Name:       "Management",
                RealmRoles: []string{"manager", "developer"},
                ClientRoles: map[string][]string{
                    "api":     {"read", "write", "admin"},
                    "reports": {"view-all"},
                },
                Members: []string{"manager@example.com"},
            },
        },
    }
    
    for _, config := range structure.Groups {
        // Create group with roles
        groupID, err := client.CreateGroupWithRoles(
            ctx,
            config.Name,
            config.RealmRoles,
            config.ClientRoles,
        )
        if err != nil {
            return fmt.Errorf("failed to create group %s: %w", config.Name, err)
        }
        
        // Add members
        for _, email := range config.Members {
            userID, err := client.GetUserIDByUsername(ctx, email, true)
            if err != nil {
                log.Printf("Warning: User %s not found\n", email)
                continue
            }
            
            err = client.AddUserToGroup(ctx, userID, groupID)
            if err != nil {
                log.Printf("Warning: Failed to add %s to group\n", email)
            }
        }
    }
    
    return nil
}
```

### Advanced Authentication
#### User Login (Password Grant)
```go
token, err := admin.Login(ctx, "username", "password", []string{"scope1", "scope2"})
if err != nil {
    // Handle error
}
// Use token.AccessToken, etc.
```

#### Start Device Login
Initiates a device code flow for user authentication.

```go
deviceResp, err := admin.StartDeviceLogin(ctx, []string{"scope1", "scope2"})
if err != nil {
    // Handle error
}
// Use deviceResp.UserCode, deviceResp.VerificationURI, etc., to prompt the user.
```

#### Poll Device Token
Polls for the token after starting device login.

```go
token, err := admin.PollDeviceToken(ctx, "device-code", 5) // Poll every 5 seconds
if err != nil {
    // Handle error
}
// Use token.AccessToken, etc.
```

#### Exchange Code for Token
Exchanges an authorization code for a token (e.g., in OAuth2 callback).

```go
token, err := admin.ExchangeCodeForToken(ctx, "auth-code", "https://example.com/callback")
if err != nil {
    // Handle error
}
// Use token.AccessToken, etc.
```

#### Generate Magic Link
Generates a magic link for passwordless login (email sending disabled by default).

```go
req := keycloaklib.MagicLinkRequest{
    Email:       "user@example.com",
    ClientID:    "client-id",
    RedirectURI: "https://example.com/redirect",
    // Other fields...
}
link, err := admin.GenerateMagicLink(ctx, req)
if err != nil {
    // Handle error
}
// Send the link to the user.
```

## Full Example: Web App Integration
For a complete example integrating this library into a web app (e.g., with Gin or Echo), see the examples directory in the repository (coming soon) or adapt the usage snippets above.

## Best Practices
- Initialize the client once and reuse it across your application for optimal performance.
- Use environment variables or secrets managers (e.g., AWS Secrets Manager) to handle sensitive data like client secrets.
- Monitor token refresh logs and API calls for rate limiting.
- Use contexts with timeouts for long-running operations.
- Validate inputs (e.g., usernames, emails) before passing to methods to prevent errors.

## Security Considerations
- Always store secrets securely and avoid hardcoding them.
- Enforce HTTPS in production; use `WithAllowInsecureHTTP(true)` only for local testing.
- Grant minimal permissions to the client ID/secret used (e.g., admin roles only when necessary).
- Avoid logging sensitive data like tokens or passwords.
- Use input validation to prevent injection attacks (built-in for queries/paths).

## Testing
Use Go's testing framework to mock HTTP responses (e.g., with `httptest`). Test token refresh, error handling, and concurrent access. Examples in the repository (coming soon).

## Contributing
Contributions are welcome! Fork the repo, create a feature branch, and submit a PR with tests. Follow Go conventions and add GoDoc comments.
