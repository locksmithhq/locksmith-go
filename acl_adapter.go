package locksmith

import (
	"context"
	"fmt"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
)

type CasbinRule struct {
	PType string  `db:"p_type" json:"p_type"`
	V0    *string `db:"v0" json:"v0,omitempty"`
	V1    *string `db:"v1" json:"v1,omitempty"`
	V2    *string `db:"v2" json:"v2,omitempty"`
	V3    *string `db:"v3" json:"v3,omitempty"`
	V4    *string `db:"v4" json:"v4,omitempty"`
	V5    *string `db:"v5" json:"v5,omitempty"`
}

type Adapter struct {
	db        Database
	tableName string
}

func NewAdapter(db *Database) *Adapter {
	return &Adapter{
		db:        *db,
		tableName: "locksmith_rules",
	}
}

func (a *Adapter) CreateTable() error {
	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id SERIAL PRIMARY KEY,
			p_type VARCHAR(100),
			v0 VARCHAR(100),
			v1 VARCHAR(100),
			v2 VARCHAR(100),
			v3 VARCHAR(100),
			v4 VARCHAR(100),
			v5 VARCHAR(100)
		);
	`, a.tableName)

	_, err := a.db.ExecContext(context.Background(), query)
	return err
}

// LoadPolicy loads all policy rules from the storage.
func (a *Adapter) LoadPolicy(model model.Model) error {
	var lines []CasbinRule
	query := fmt.Sprintf("SELECT p_type, v0, v1, v2, v3, v4, v5 FROM %s", a.tableName)

	rows, err := a.db.QueryContext(context.Background(), query)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var line CasbinRule
		if err := rows.Scan(
			&line.PType,
			&line.V0,
			&line.V1,
			&line.V2,
			&line.V3,
			&line.V4,
			&line.V5,
		); err != nil {
			return err
		}
		lines = append(lines, line)
	}

	for _, line := range lines {
		loadPolicyLine(&line, model)
	}
	return nil
}

// SavePolicy saves all policy rules to the storage.
func (a *Adapter) SavePolicy(model model.Model) error {
	_, err := a.db.ExecContext(context.Background(), fmt.Sprintf("DELETE FROM %s", a.tableName))
	if err != nil {
		return err
	}

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			if err := a.AddPolicy("p", ptype, rule); err != nil {
				return err
			}
		}
	}

	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			if err := a.AddPolicy("g", ptype, rule); err != nil {
				return err
			}
		}
	}

	return nil
}

// AddPolicy adds a policy rule to the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	query := fmt.Sprintf("INSERT INTO %s (p_type, v0, v1, v2, v3, v4, v5) VALUES ($1, $2, $3, $4, $5, $6, $7)", a.tableName)
	_, err := a.db.ExecContext(context.Background(), query, line.PType, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5)
	return err
}

// RemovePolicy removes a policy rule from the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	line := savePolicyLine(ptype, rule)

	query := fmt.Sprintf(`
		DELETE FROM %s 
		WHERE p_type = $1 
		AND v0 IS NOT DISTINCT FROM $2 
		AND v1 IS NOT DISTINCT FROM $3 
		AND v2 IS NOT DISTINCT FROM $4 
		AND v3 IS NOT DISTINCT FROM $5 
		AND v4 IS NOT DISTINCT FROM $6 
		AND v5 IS NOT DISTINCT FROM $7
	`, a.tableName)
	_, err := a.db.ExecContext(context.Background(), query, line.PType, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5)
	return err
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	args := []interface{}{ptype}
	where := []string{"p_type = $1"}

	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		val := fieldValues[0-fieldIndex]
		if val != "" {
			where = append(where, fmt.Sprintf("v0 IS NOT DISTINCT FROM $%d", len(args)+1))
			args = append(args, val)
		}
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		val := fieldValues[1-fieldIndex]
		if val != "" {
			where = append(where, fmt.Sprintf("v1 IS NOT DISTINCT FROM $%d", len(args)+1))
			args = append(args, val)
		}
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		val := fieldValues[2-fieldIndex]
		if val != "" {
			where = append(where, fmt.Sprintf("v2 IS NOT DISTINCT FROM $%d", len(args)+1))
			args = append(args, val)
		}
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		val := fieldValues[3-fieldIndex]
		if val != "" {
			where = append(where, fmt.Sprintf("v3 IS NOT DISTINCT FROM $%d", len(args)+1))
			args = append(args, val)
		}
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		val := fieldValues[4-fieldIndex]
		if val != "" {
			where = append(where, fmt.Sprintf("v4 IS NOT DISTINCT FROM $%d", len(args)+1))
			args = append(args, val)
		}
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		val := fieldValues[5-fieldIndex]
		if val != "" {
			where = append(where, fmt.Sprintf("v5 IS NOT DISTINCT FROM $%d", len(args)+1))
			args = append(args, val)
		}
	}

	query := fmt.Sprintf("DELETE FROM %s WHERE %s", a.tableName, strings.Join(where, " AND "))
	_, err := a.db.ExecContext(context.Background(), query, args...)
	return err
}

// UpdatePolicy updates a policy rule from the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) UpdatePolicy(sec string, ptype string, oldRule, newRule []string) error {
	oldLine := savePolicyLine(ptype, oldRule)
	newLine := savePolicyLine(ptype, newRule)

	query := fmt.Sprintf(`
		UPDATE %s 
		SET v0 = $1, v1 = $2, v2 = $3, v3 = $4, v4 = $5, v5 = $6
		WHERE p_type = $7 
		AND v0 IS NOT DISTINCT FROM $8 
		AND v1 IS NOT DISTINCT FROM $9 
		AND v2 IS NOT DISTINCT FROM $10 
		AND v3 IS NOT DISTINCT FROM $11 
		AND v4 IS NOT DISTINCT FROM $12 
		AND v5 IS NOT DISTINCT FROM $13
	`, a.tableName)

	_, err := a.db.ExecContext(context.Background(), query,
		newLine.V0, newLine.V1, newLine.V2, newLine.V3, newLine.V4, newLine.V5,
		ptype, oldLine.V0, oldLine.V1, oldLine.V2, oldLine.V3, oldLine.V4, oldLine.V5,
	)
	return err
}

// UpdateGroupingPolicy updates a grouping policy rule from the storage.
// This is part of the Auto-Save feature.
func (a *Adapter) UpdateGroupingPolicy(sec string, ptype string, oldRule, newRule []string) error {
	return a.UpdatePolicy(sec, ptype, oldRule, newRule)
}

// UpdatePolicies updates multiple policy rules from the storage.
func (a *Adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	for i := range oldRules {
		err := a.UpdatePolicy(sec, ptype, oldRules[i], newRules[i])
		if err != nil {
			return err
		}
	}
	return nil
}

// UpdateFilteredPolicies updates policy rules that match the filter from the storage.
func (a *Adapter) UpdateFilteredPolicies(sec string, ptype string, newPolicies [][]string, fieldIndex int, fieldValues ...string) ([][]string, error) {
	return nil, nil
}

func loadPolicyLine(line *CasbinRule, model model.Model) {
	lineText := line.PType
	if line.V0 != nil && *line.V0 != "" {
		lineText += ", " + *line.V0
	}
	if line.V1 != nil && *line.V1 != "" {
		lineText += ", " + *line.V1
	}
	if line.V2 != nil && *line.V2 != "" {
		lineText += ", " + *line.V2
	}
	if line.V3 != nil && *line.V3 != "" {
		lineText += ", " + *line.V3
	}
	if line.V4 != nil && *line.V4 != "" {
		lineText += ", " + *line.V4
	}
	if line.V5 != nil && *line.V5 != "" {
		lineText += ", " + *line.V5
	}

	persist.LoadPolicyLine(lineText, model)
}

func savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{PType: ptype}

	if len(rule) > 0 {
		line.V0 = &rule[0]
	}
	if len(rule) > 1 {
		line.V1 = &rule[1]
	}
	if len(rule) > 2 {
		line.V2 = &rule[2]
	}
	if len(rule) > 3 {
		line.V3 = &rule[3]
	}
	if len(rule) > 4 {
		line.V4 = &rule[4]
	}
	if len(rule) > 5 {
		line.V5 = &rule[5]
	}

	return line
}
