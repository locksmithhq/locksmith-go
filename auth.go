package locksmith

import (
	"context"
	"time"

	"github.com/booscaaa/initializers/auth"
	"github.com/golang-jwt/jwt/v5"
)

type Authenticator struct {
	*auth.Authenticator
}

type internalClaims struct {
	Data map[auth.ContextValue]any
	jwt.RegisteredClaims
}

type TokenClaims struct {
	Sub    string `json:"sub"`
	Client string `json:"client"`
	Domain string `json:"domain"`
}

// GetFields implements auth.CustomClaims.
func (t TokenClaims) GetFields() map[auth.ContextValue]any {
	return map[auth.ContextValue]any{
		"sub":    t.Sub,
		"client": t.Client,
		"domain": t.Domain,
	}
}

func NewTokenClaims(sub string, client string, domain string) *TokenClaims {
	return &TokenClaims{
		Sub:    sub,
		Client: client,
		Domain: domain,
	}
}

func NewAuthenticator(clientSecret string) *Authenticator {
	return &Authenticator{
		Authenticator: auth.Initialize(clientSecret, &TokenClaims{}),
	}
}

func VerifyToken(bearerToken string) (internalClaims, bool) {
	return verifyToken(bearerToken, locksmithInstance.clientSecret)
}

func VerifyTokenWithClientSecret(bearerToken string, clientSecret string) (internalClaims, bool) {
	return verifyToken(bearerToken, clientSecret)
}

func verifyToken(bearerToken string, clientSecret string) (internalClaims, bool) {
	c := &TokenClaims{}
	claims := &internalClaims{Data: c.GetFields()}

	token, err := jwt.ParseWithClaims(bearerToken, claims, func(token *jwt.Token) (any, error) {
		return []byte(clientSecret), nil
	})

	if err != nil {
		return internalClaims{}, false
	}

	if !token.Valid || claims.ExpiresAt == nil {
		return internalClaims{}, false
	}

	return *claims, true
}

func GetSignToken(claims *TokenClaims, duration time.Duration, clientSecret string) string {
	return auth.GetSignToken(claims, duration, clientSecret)
}

func GetSubFromContext(ctx context.Context) string {
	return auth.GetStringFromContext(ctx, "sub")
}

func GetClientFromContext(ctx context.Context) string {
	return auth.GetStringFromContext(ctx, "client")
}

func GetDomainFromContext(ctx context.Context) string {
	return auth.GetStringFromContext(ctx, "domain")
}
