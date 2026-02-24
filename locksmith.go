package locksmith

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

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

type permissionsOutput struct {
	Permissions []actionOutput `json:"permissions"`
}

type actionOutput struct {
	Role   string `json:"role"`
	Domain string `json:"domain"`
	Module string `json:"module"`
	Action string `json:"action"`
}

type accountInput struct {
	Id       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
	RoleName string `json:"role_name"`
}

type accountOutput struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Username string `json:"username"`
	RoleName string `json:"role_name"`
}

type accessTokenInput struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Code         string `json:"code"`
	GrantType    string `json:"grant_type"`
}

type refreshAccessTokenInput struct {
	RefreshToken string `json:"refresh_token"`
	GrantType    string `json:"grant_type"`
}

type accessTokenOutput struct {
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

func NewRefreshAccessTokenInput(
	refreshToken string,
) refreshAccessTokenInput {
	return refreshAccessTokenInput{
		RefreshToken: refreshToken,
	}
}

func NewAccessTokenInput(
	code string,
) accessTokenInput {
	return accessTokenInput{
		Code: code,
	}
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

func GenerateAccessToken(ctx context.Context, input accessTokenInput) (accessTokenOutput, error) {
	output, err := locksmithInstance.generateAccessToken(ctx, input)
	if err != nil {
		return accessTokenOutput{}, err
	}

	return output, nil
}

func GenerateRefreshToken(ctx context.Context, input refreshAccessTokenInput) (accessTokenOutput, error) {
	output, err := locksmithInstance.generateRefreshToken(ctx, input)
	if err != nil {
		return accessTokenOutput{}, err
	}

	return output, nil
}

func CreateAccount(ctx context.Context, input accountInput) (accountOutput, error) {
	output, err := locksmithInstance.createAccount(ctx, input)
	if err != nil {
		return accountOutput{}, err
	}

	return output, nil
}

func UpdateAccount(ctx context.Context, input accountInput) (accountOutput, error) {
	output, err := locksmithInstance.updateAccount(ctx, input)
	if err != nil {
		return accountOutput{}, err
	}

	return output, nil
}

func GetAccountByID(ctx context.Context, id string) (accountOutput, error) {
	output, err := locksmithInstance.getAccountByID(ctx, id)
	if err != nil {
		return accountOutput{}, err
	}

	return output, nil
}

func GetPermissionsForUser(ctx context.Context, sub string, dom string) (permissionsOutput, error) {
	output, err := locksmithInstance.getPermissionsForUserInDomain(ctx, sub, dom)
	if err != nil {
		return permissionsOutput{}, err
	}

	return output, nil
}

func HttpEnforce(ctx context.Context, sub string, domain string, obj string, act string) (bool, error) {
	output, err := locksmithInstance.enforce(ctx, sub, domain, obj, act)
	if err != nil {
		return false, nil
	}

	return output, nil
}

func NewAccountInput(
	id string,
	name string,
	email string,
	username string,
	password string,
	roleName string,
) accountInput {
	return accountInput{
		Id:       id,
		Name:     name,
		Email:    email,
		Username: username,
		Password: password,
		RoleName: roleName,
	}
}
