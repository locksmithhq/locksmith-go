package locksmith

import (
	_ "embed"
	"errors"
	"fmt"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/rbac"
)

//go:embed model.conf
var modelConf string

type Service struct {
	enforcer *casbin.Enforcer
}

func checkEnforcer() error {
	if err := checkInitialized(); err != nil {
		return err
	}
	if locksmithInstance.acl.enforcer == nil {
		return errors.New("locksmith: local ACL not configured — initialize with a non-nil database")
	}
	return nil
}

func NewAcl(enforcer *casbin.Enforcer) *Service {
	return &Service{
		enforcer: enforcer,
	}
}

func newEnforcer(db *Database) (*casbin.Enforcer, error) {
	adapter := NewAdapter(db)

	if err := adapter.CreateTable(); err != nil {
		return nil, fmt.Errorf("failed to create casbin table: %w", err)
	}

	m, err := model.NewModelFromString(modelConf)
	if err != nil {
		return nil, fmt.Errorf("failed to load casbin model: %w", err)
	}

	enforcer, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("failed to create enforcer: %w", err)
	}

	if err := enforcer.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	enforcer.EnableAutoSave(true)

	return enforcer, nil
}

func Enforce(sub, dom, obj, act string) (bool, error) {
	if err := checkEnforcer(); err != nil {
		return false, err
	}
	return locksmithInstance.acl.enforcer.Enforce(sub, dom, obj, act)
}

func LoadPolicy() error {
	if err := checkEnforcer(); err != nil {
		return err
	}
	return locksmithInstance.acl.enforcer.LoadPolicy()
}

func AddPolicy(sub, dom, obj, act string) (bool, error) {
	if err := checkEnforcer(); err != nil {
		return false, err
	}
	return locksmithInstance.acl.enforcer.AddPolicy(sub, dom, obj, act)
}

func RemovePolicy(sub, dom, obj, act string) (bool, error) {
	if err := checkEnforcer(); err != nil {
		return false, err
	}
	return locksmithInstance.acl.enforcer.RemovePolicy(sub, dom, obj, act)
}

func AddRoleForUser(user, role, dom string) (bool, error) {
	if err := checkEnforcer(); err != nil {
		return false, err
	}
	return locksmithInstance.acl.enforcer.AddGroupingPolicy(user, role, dom)
}

func RemoveRoleForUser(user, role, dom string) (bool, error) {
	if err := checkEnforcer(); err != nil {
		return false, err
	}
	return locksmithInstance.acl.enforcer.RemoveGroupingPolicy(user, role, dom)
}

func DeleteRolesForUser(user string, dom string) (bool, error) {
	if err := checkEnforcer(); err != nil {
		return false, err
	}
	return locksmithInstance.acl.enforcer.DeleteRolesForUser(user, dom)
}

func GetRolesForUser(user string, dom string) ([]string, error) {
	if err := checkEnforcer(); err != nil {
		return nil, err
	}
	return locksmithInstance.acl.enforcer.GetRolesForUser(user, dom)
}

func GetUsersForRole(role string) ([]string, error) {
	if err := checkEnforcer(); err != nil {
		return nil, err
	}
	return locksmithInstance.acl.enforcer.GetUsersForRole(role)
}

func GetAllRolesByDomain(dom string) ([]string, error) {
	if err := checkEnforcer(); err != nil {
		return nil, err
	}
	return locksmithInstance.acl.enforcer.GetAllRolesByDomain(dom)
}

func GetAllUsersByDomain(dom string) ([]string, error) {
	if err := checkEnforcer(); err != nil {
		return nil, err
	}
	return locksmithInstance.acl.enforcer.GetAllUsersByDomain(dom)
}

func GetAllDomains() ([]string, error) {
	if err := checkEnforcer(); err != nil {
		return nil, err
	}
	return locksmithInstance.acl.enforcer.GetAllDomains()
}

func GetUsersForRoleInDomain(role, dom string) []string {
	return locksmithInstance.acl.enforcer.GetUsersForRoleInDomain(role, dom)
}

func GetPermissionsForUserInDomain(user, dom string) [][]string {
	return locksmithInstance.acl.enforcer.GetPermissionsForUserInDomain(user, dom)
}

func AddRolesForUser(user string, roles []string, dom string) (bool, error) {
	if err := checkEnforcer(); err != nil {
		return false, err
	}
	return locksmithInstance.acl.enforcer.AddRolesForUser(user, roles, dom)
}

func AddPolicies(policies [][]string) (bool, error) {
	if err := checkEnforcer(); err != nil {
		return false, err
	}
	return locksmithInstance.acl.enforcer.AddPolicies(policies)
}

func GetAllActions() ([]string, error) {
	if err := checkEnforcer(); err != nil {
		return nil, err
	}
	return locksmithInstance.acl.enforcer.GetAllActions()
}

func GetAllObjects() ([]string, error) {
	if err := checkEnforcer(); err != nil {
		return nil, err
	}
	return locksmithInstance.acl.enforcer.GetAllObjects()
}

func UpdateGroupingPolicy(oldRule, newRule []string) (bool, error) {
	if err := checkEnforcer(); err != nil {
		return false, err
	}
	return locksmithInstance.acl.enforcer.UpdateGroupingPolicy(oldRule, newRule)
}

func GetFilteredPolicy(fieldIndex int, fieldValues ...string) ([][]string, error) {
	if err := checkEnforcer(); err != nil {
		return nil, err
	}
	return locksmithInstance.acl.enforcer.GetFilteredPolicy(fieldIndex, fieldValues...)
}

func UpdatePolicy(oldRule, newRule []string) (bool, error) {
	if err := checkEnforcer(); err != nil {
		return false, err
	}
	return locksmithInstance.acl.enforcer.UpdatePolicy(oldRule, newRule)
}

func RemoveFilteredPolicy(fieldIndex int, fieldValues ...string) (bool, error) {
	if err := checkEnforcer(); err != nil {
		return false, err
	}
	return locksmithInstance.acl.enforcer.RemoveFilteredPolicy(fieldIndex, fieldValues...)
}

func RemoveFilteredGroupingPolicy(fieldIndex int, fieldValues ...string) (bool, error) {
	if err := checkEnforcer(); err != nil {
		return false, err
	}
	return locksmithInstance.acl.enforcer.RemoveFilteredGroupingPolicy(fieldIndex, fieldValues...)
}

func GetRolesForUserInDomain(user, dom string) []string {
	return locksmithInstance.acl.enforcer.GetRolesForUserInDomain(user, dom)
}

func GetDomainsForUser(user string) ([]string, error) {
	if err := checkEnforcer(); err != nil {
		return nil, err
	}
	return locksmithInstance.acl.enforcer.GetDomainsForUser(user)
}

func GetRoleManager() rbac.RoleManager {
	return locksmithInstance.acl.enforcer.GetRoleManager()
}
