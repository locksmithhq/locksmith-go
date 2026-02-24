# locksmith-go

Go SDK for integrating with the [Locksmith](https://github.com/locksmith/locksmith) identity and access management server.

It provides:
- **OAuth2** — access token and refresh token generation
- **JWT** — token signing, verification, and context helpers
- **ACL / RBAC** — domain-aware role and policy management powered by [Casbin](https://casbin.org/)
- **HTTP Middlewares** — plug-and-play authentication and authorization for any `net/http`-compatible router

---

## Installation

```bash
go get github.com/locksmithhq/locksmith-go
```

---

## Prerequisites

### Casbin model file

The SDK uses a Casbin RBAC model with domains. Create a `model.conf` file in the root of your application (or set `CASBIN_MODEL_PATH` to a custom path):

```ini
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
```

> The SDK automatically creates the `locksmith_rules` table in your database on first run.

---

## Initialization

Call `Initialize` once at application startup, before using any other function.

```go
import locksmith "github.com/locksmithhq/locksmith-go"

func main() {
    db, _ := sql.Open("postgres", os.Getenv("DATABASE_URL"))

    err := locksmith.Initialize(
        db,                          // database.sql-compatible connection (used for ACL storage)
        "https://locksmith.example.com", // Locksmith server base URL
        "my-client-id",              // OAuth2 client ID
        "my-client-secret",          // OAuth2 client secret
    )
    if err != nil {
        log.Fatal(err)
    }
}
```

### Without local ACL (HTTP-only mode)

If you do not need local Casbin enforcement and prefer to delegate every authorization check to the Locksmith server, pass `nil` as the database and enable the `WithHttpEnforce` option:

```go
err := locksmith.Initialize(
    nil,
    "https://locksmith.example.com",
    "my-client-id",
    "my-client-secret",
    locksmith.WithHttpEnforce(), // delegate enforce calls to the server over HTTP
)
```

> **Security notice:** `WithHttpEnforce` transmits the `clientSecret` in the request body to the `/api/acl/enforce` endpoint. Always use **TLS (HTTPS)** when this option is active.

---

## OAuth2

### Generate an access token

Exchange an authorization code for an access/refresh token pair.

```go
input := locksmith.NewAccessTokenInput("AUTHORIZATION_CODE_FROM_CALLBACK")

token, err := locksmith.GenerateAccessToken(ctx, input)
if err != nil {
    // handle error
}

fmt.Println(token.AccessToken)  // JWT access token
fmt.Println(token.RefreshToken) // opaque refresh token
fmt.Println(token.ExpiresIn)    // seconds until expiry
fmt.Println(token.TokenType)    // "Bearer"
```

### Refresh an access token

```go
input := locksmith.NewRefreshAccessTokenInput("REFRESH_TOKEN")

token, err := locksmith.GenerateRefreshToken(ctx, input)
if err != nil {
    // handle error
}

fmt.Println(token.AccessToken)
```

---

## Account Management

These calls authenticate to the Locksmith server using Basic Auth (client credentials).

### Create an account

```go
input := locksmith.NewAccountInput(
    "",               // id — leave empty to auto-generate
    "Jane Doe",       // name
    "jane@example.com", // email
    "janedoe",        // username
    "s3cr3t",         // password
    "admin",          // role name
)

account, err := locksmith.CreateAccount(ctx, input)
if err != nil {
    // handle error
}

fmt.Println(account.ID, account.Email)
```

### Update an account

```go
input := locksmith.NewAccountInput(
    "user-uuid-here",
    "Jane Smith",
    "jane@example.com",
    "janedoe",
    "",      // password — leave empty to keep existing
    "editor",
)

account, err := locksmith.UpdateAccount(ctx, input)
```

### Get an account by ID

```go
account, err := locksmith.GetAccountByID(ctx, "user-uuid-here")
if err != nil {
    // handle error
}

fmt.Println(account.Name, account.RoleName)
```

---

## JWT

### Sign a token manually

Useful for service-to-service calls or custom token issuance.

```go
claims := locksmith.NewTokenClaims(
    "user-uuid",    // sub
    "my-client-id", // client
    "tenant-a",     // domain
)

token := locksmith.GetSignToken(claims, 24*time.Hour, "my-client-secret")
```

### Verify a token

```go
claims, ok := locksmith.VerifyToken("eyJhbGci...")
if !ok {
    // token is invalid or expired
}
```

Verify a token issued by a different client secret:

```go
claims, ok := locksmith.VerifyTokenWithClientSecret("eyJhbGci...", "other-secret")
```

### Extract claims from context

After `AuthMiddleware` runs, the JWT claims are stored in the request context and can be retrieved anywhere downstream:

```go
func myHandler(w http.ResponseWriter, r *http.Request) {
    sub    := locksmith.GetSubFromContext(r.Context())    // user ID
    client := locksmith.GetClientFromContext(r.Context()) // client ID
    domain := locksmith.GetDomainFromContext(r.Context()) // tenant / domain
}
```

---

## HTTP Middlewares

All middlewares are compatible with the standard `net/http` interface and work with any router that supports `http.Handler` chains (chi, gorilla/mux, stdlib, etc.).

### AuthMiddleware — Bearer token (Authorization header)

Validates the JWT from the `Authorization: Bearer <token>` header and populates the context with claims.

```go
import "github.com/go-chi/chi/v5"

r := chi.NewRouter()
r.Use(locksmith.AuthMiddleware)

r.Get("/profile", func(w http.ResponseWriter, r *http.Request) {
    sub := locksmith.GetSubFromContext(r.Context())
    w.Write([]byte("Hello, " + sub))
})
```

### AuthMiddlewareCookie — Cookie-based token

Validates the JWT from a named cookie.

```go
r.Use(locksmith.AuthMiddlewareCookie("session"))
```

### AclMiddleware — Policy enforcement

Checks whether the authenticated user (`sub` from context) has permission to perform `act` on `obj` within `domain`. Returns `403 Forbidden` if the check fails.

```go
// Signature: AclMiddleware(domain, object, action)
r.With(locksmith.AclMiddleware("tenant-a", "reports", "read")).
    Get("/reports", reportsHandler)

r.With(locksmith.AclMiddleware("tenant-a", "reports", "write")).
    Post("/reports", createReportHandler)
```

### Full router example (chi)

```go
func main() {
    db, _ := sql.Open("postgres", os.Getenv("DATABASE_URL"))
    locksmith.Initialize(db, "https://locksmith.example.com", "client-id", "client-secret")

    r := chi.NewRouter()

    // Public routes
    r.Post("/oauth/token", tokenHandler)

    // Authenticated routes
    r.Group(func(r chi.Router) {
        r.Use(locksmith.AuthMiddleware)

        r.Get("/me", meHandler)

        // With ACL enforcement
        r.With(locksmith.AclMiddleware("acme-corp", "invoices", "read")).
            Get("/invoices", listInvoicesHandler)

        r.With(locksmith.AclMiddleware("acme-corp", "invoices", "write")).
            Post("/invoices", createInvoiceHandler)

        r.With(locksmith.AclMiddleware("acme-corp", "invoices", "delete")).
            Delete("/invoices/{id}", deleteInvoiceHandler)
    })

    http.ListenAndServe(":8080", r)
}
```

---

## ACL / RBAC

The ACL functions are thin wrappers over the Casbin enforcer. Policies follow the pattern `(subject, domain, object, action)`.

> These functions require a database connection (i.e. `db != nil` in `Initialize`).

### Policy management

```go
// Add a policy: role "admin" in domain "acme-corp" can "write" on "invoices"
locksmith.AddPolicy("admin", "acme-corp", "invoices", "write")

// Remove a policy
locksmith.RemovePolicy("admin", "acme-corp", "invoices", "write")

// Add multiple policies at once
locksmith.AddPolicies([][]string{
    {"editor", "acme-corp", "posts", "read"},
    {"editor", "acme-corp", "posts", "write"},
})

// Update a policy
locksmith.UpdatePolicy(
    []string{"editor", "acme-corp", "posts", "read"},
    []string{"editor", "acme-corp", "articles", "read"},
)

// Remove policies matching a filter (fieldIndex is 0-based column index)
// Example: remove all policies for domain "acme-corp"
locksmith.RemoveFilteredPolicy(1, "acme-corp")

// Check a specific permission directly
allowed, err := locksmith.Enforce("user:uuid-here", "acme-corp", "invoices", "write")
```

### Role management

```go
// Assign role "admin" to user in domain "acme-corp"
locksmith.AddRoleForUser("user:uuid-here", "admin", "acme-corp")

// Assign multiple roles at once
locksmith.AddRolesForUser("user:uuid-here", []string{"editor", "viewer"}, "acme-corp")

// Remove a specific role assignment
locksmith.RemoveRoleForUser("user:uuid-here", "admin", "acme-corp")

// Remove all roles for a user in a domain
locksmith.DeleteRolesForUser("user:uuid-here", "acme-corp")

// Update a grouping policy (rename role assignment)
locksmith.UpdateGroupingPolicy(
    []string{"user:uuid-here", "editor", "acme-corp"},
    []string{"user:uuid-here", "admin",  "acme-corp"},
)

// Remove grouping policies matching a filter
locksmith.RemoveFilteredGroupingPolicy(2, "acme-corp") // all assignments in domain
```

### Queries

```go
// Roles assigned to a user in a domain
roles, _ := locksmith.GetRolesForUser("user:uuid-here", "acme-corp")

// Roles assigned to a user in a domain (slice, no error)
roles := locksmith.GetRolesForUserInDomain("user:uuid-here", "acme-corp")

// All users that have a given role
users, _ := locksmith.GetUsersForRole("admin")

// All users with any role in a domain
users, _ := locksmith.GetUsersForRoleInDomain("admin", "acme-corp")

// All users in a domain
users, _ := locksmith.GetAllUsersByDomain("acme-corp")

// All roles in a domain
roles, _ := locksmith.GetAllRolesByDomain("acme-corp")

// All known domains
domains, _ := locksmith.GetAllDomains()

// All domains a user belongs to
domains, _ := locksmith.GetDomainsForUser("user:uuid-here")

// Flat permission list for a user in a domain (raw Casbin rows)
perms := locksmith.GetPermissionsForUserInDomain("user:uuid-here", "acme-corp")

// Via the Locksmith server (returns structured output)
output, _ := locksmith.GetPermissionsForUser(ctx, "user:uuid-here", "acme-corp")
for _, p := range output.Permissions {
    fmt.Printf("role=%s domain=%s module=%s action=%s\n", p.Role, p.Domain, p.Module, p.Action)
}

// All registered objects and actions in the policy
objects, _ := locksmith.GetAllObjects()
actions, _ := locksmith.GetAllActions()

// Filtered policy query (fieldIndex is 0-based)
// Example: all policies for subject "admin"
rows, _ := locksmith.GetFilteredPolicy(0, "admin")

// Advanced: access the underlying Casbin RoleManager
rm := locksmith.GetRoleManager()

// Reload policies from database
locksmith.LoadPolicy()
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CASBIN_MODEL_PATH` | `model.conf` (working dir) | Path to the Casbin model configuration file |

---

## Error Handling

HTTP errors from the Locksmith server are returned as `ApiError`:

```go
token, err := locksmith.GenerateAccessToken(ctx, input)
if err != nil {
    var apiErr locksmith.ApiError
    if errors.As(err, &apiErr) {
        fmt.Println(apiErr.Message) // human-readable message
        fmt.Println(apiErr.Local)   // where the error occurred
        fmt.Println(apiErr.Err)     // underlying error string
        fmt.Println(apiErr.Trace)   // stack trace (if available)
    }
}
```
