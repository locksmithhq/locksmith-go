package locksmith

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"

	"github.com/casbin/casbin/v2"
)

type Database interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

var locksmithInstance *locksmith

type ApiError struct {
	Message string `json:"message"`
	Local   string `json:"local"`
	Err     string `json:"err"`
	Trace   string `json:"trace"`
}

func (e ApiError) Error() string {
	return fmt.Sprintf("Error: %s\n  at %s\n  error: %s\n  trace: %s", e.Message, e.Local, e.Err, e.Trace)
}

type PermissionsOutput struct {
	Permissions []ActionOutput `json:"permissions"`
}

type ActionOutput struct {
	Role   string `json:"role"`
	Domain string `json:"domain"`
	Module string `json:"module"`
	Action string `json:"action"`
}

type AccountInput struct {
	Id                 string `json:"id"`
	Name               string `json:"name"`
	Email              string `json:"email"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	RoleName           string `json:"role_name"`
	MustChangePassword bool   `json:"must_change_password"`
}

type AccountOutput struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Email              string `json:"email"`
	Username           string `json:"username"`
	RoleName           string `json:"role_name"`
	MustChangePassword bool   `json:"must_change_password"`
}

type AccessTokenInput struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	GrantType    string `json:"grant_type"`
	CodeVerifier string `json:"code_verifier"`
}

type RefreshAccessTokenInput struct {
	RefreshToken string `json:"refresh_token"`
	GrantType    string `json:"grant_type"`
}

type AccessTokenOutput struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
}

type locksmith struct {
	baseUrl      string
	clientID     string
	clientSecret string
	acl          *Service
	auth         *Authenticator
	httpEnforce  bool
}

type locksmithOption func(*locksmith)

// WithHttpEnforce configures the SDK to delegate policy enforcement to the
// Locksmith server via HTTP instead of using the local Casbin enforcer.
//
// WARNING: when this option is active, the clientSecret is transmitted in the
// request body to the /api/acl/enforce endpoint. Ensure the Locksmith server
// is reachable exclusively over TLS (HTTPS) to prevent secret exposure.
func WithHttpEnforce() locksmithOption {
	return func(l *locksmith) {
		l.httpEnforce = true
	}
}

func checkInitialized() error {
	if locksmithInstance == nil {
		return errors.New("locksmith: not initialized — call locksmith.Initialize first")
	}
	return nil
}

func Initialize(db Database, baseUrl string, clientID string, clientSecret string, options ...locksmithOption) error {
	if baseUrl == "" {
		return errors.New("base_url is required")
	}

	if clientID == "" || clientSecret == "" {
		return errors.New("client_id and client_secret are required")
	}

	var enforcer *casbin.Enforcer
	if db != nil {
		var err error
		enforcer, err = newEnforcer(&db)
		if err != nil {
			return err
		}
	}

	locksmithInstance = &locksmith{
		baseUrl:      baseUrl,
		clientID:     clientID,
		clientSecret: clientSecret,
		acl:          NewAcl(enforcer),
		auth:         NewAuthenticator(clientSecret),
	}

	for _, option := range options {
		option(locksmithInstance)
	}

	return nil
}

func GenerateAccessToken(ctx context.Context, r *http.Request, input AccessTokenInput) (AccessTokenOutput, error) {
	if err := checkInitialized(); err != nil {
		return AccessTokenOutput{}, err
	}
	return locksmithInstance.generateAccessToken(ctx, r, input)
}

func GenerateRefreshToken(ctx context.Context, input RefreshAccessTokenInput) (AccessTokenOutput, error) {
	if err := checkInitialized(); err != nil {
		return AccessTokenOutput{}, err
	}
	return locksmithInstance.generateRefreshToken(ctx, input)
}

func CreateAccount(ctx context.Context, input AccountInput) (AccountOutput, error) {
	if err := checkInitialized(); err != nil {
		return AccountOutput{}, err
	}
	return locksmithInstance.createAccount(ctx, input)
}

func UpdateAccount(ctx context.Context, input AccountInput) (AccountOutput, error) {
	if err := checkInitialized(); err != nil {
		return AccountOutput{}, err
	}
	return locksmithInstance.updateAccount(ctx, input)
}

func GetAccountByID(ctx context.Context, id string) (AccountOutput, error) {
	if err := checkInitialized(); err != nil {
		return AccountOutput{}, err
	}
	return locksmithInstance.getAccountByID(ctx, id)
}

func GetPermissionsForUser(ctx context.Context, sub string, dom string) (PermissionsOutput, error) {
	if err := checkInitialized(); err != nil {
		return PermissionsOutput{}, err
	}
	return locksmithInstance.getPermissionsForUserInDomain(ctx, sub, dom)
}

func HttpEnforce(ctx context.Context, sub string, domain string, obj string, act string) (bool, error) {
	if err := checkInitialized(); err != nil {
		return false, err
	}
	return locksmithInstance.enforce(ctx, sub, domain, obj, act)
}
