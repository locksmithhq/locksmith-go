package locksmith

import (
	"context"
	"net/http"
	"strings"

	"github.com/booscaaa/initializers/auth"
)

// contextKey is a typed key for context values, preventing collisions across packages.
type contextKey string

// jwtContextKey is the typed key used internally to store and retrieve the JWT token.
const jwtContextKey contextKey = "jwt"

type Authorizer func(next http.Handler) http.Handler

// AclMiddleware returns a middleware that enforces the policy for a given domain, object, and action.
// sub is determined from the request context (simulated or real).
func AclMiddleware(domain string, obj string, act string) Authorizer {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sub := "user:" + auth.GetStringFromContext(r.Context(), "sub")

			allowed, err := locksmithInstance.enforce(r.Context(), sub, domain, obj, act)
			if err != nil {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			if !allowed {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func AuthMiddlewareCookie(cookieName string) Authorizer {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookieValue := ""
			cookies := r.Cookies()
			for _, cookie := range cookies {
				if cookie.Name == cookieName {
					cookieValue = cookie.Value
					break
				}
			}

			if cookieValue == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Store with untyped string key for auth library compatibility,
			// and with typed key for safe internal retrieval.
			ctx := context.WithValue(r.Context(), "jwt", cookieValue)
			ctx = context.WithValue(ctx, jwtContextKey, cookieValue)
			locksmithInstance.auth.AuthMiddleware(cookieName, "sub", "client", "domain")(next).ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerToken := r.Header.Get("Authorization")

		strArr := strings.Split(headerToken, " ")
		if len(strArr) == 2 {
			headerToken = strArr[1]
		}
		// Store with untyped string key for auth library compatibility,
		// and with typed key for safe internal retrieval.
		ctx := context.WithValue(r.Context(), "jwt", headerToken)
		ctx = context.WithValue(ctx, jwtContextKey, headerToken)
		locksmithInstance.auth.AuthMiddleware("", "sub", "client", "domain")(next).ServeHTTP(w, r.WithContext(ctx))
	})
}
