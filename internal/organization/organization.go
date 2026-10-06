package organization

import (
	"errors"

	"secrust/internal/database"
)

type Organization struct {
	ID   int
	Name string
}

// ==========================================
// Create Organization
// ==========================================

func Create(name string) (int, error) {

	if name == "" {
		return 0, errors.New("organization name required")
	}

	result, err := database.DB.Exec(
		`
		INSERT INTO organizations(name)
		VALUES(?)
		`,
		name,
	)

	if err != nil {
		return 0, err
	}

	id, err := result.LastInsertId()

	if err != nil {
		return 0, err
	}

	return int(id), nil
}

// ==========================================
// Add User To Organization
// ==========================================

func AddUser(
	organizationID int,
	userID int,
	role string,
) error {

	_, err := database.DB.Exec(
		`
		INSERT INTO organization_users(
			organization_id,
			user_id,
			role
		)
		VALUES(?,?,?)
		`,
		organizationID,
		userID,
		role,
	)

	return err
}

// ==========================================
// Get User Organization
// ==========================================

func GetUserOrganization(
	userID interface{},
) (int, string, string, error) {

	var organizationID int
	var organizationName string
	var role string

	err := database.DB.QueryRow(
		`
		SELECT
			o.id,
			o.name,
			ou.role
		FROM organization_users ou
		JOIN organizations o
			ON o.id = ou.organization_id
		WHERE ou.user_id=?
		LIMIT 1
		`,
		userID,
	).Scan(
		&organizationID,
		&organizationName,
		&role,
	)

	if err != nil {
		return 0, "", "", errors.New(
			"organization not found",
		)
	}

	return organizationID, organizationName, role, nil
}
