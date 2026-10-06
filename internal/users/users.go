package users

import (
	"errors"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"secrust/internal/database"
)

type User struct {
	ID     int
	Name   string
	Email  string
	Role   string
	Status string
}

// ==========================================
// Create User
// ==========================================

func CreateUser(
	name string,
	email string,
	password string,
	role string,
	organizationID int,
) (int, error) {

	name = strings.TrimSpace(name)
	email = strings.ToLower(strings.TrimSpace(email))
	role = strings.ToUpper(strings.TrimSpace(role))

	if name == "" ||
		email == "" ||
		password == "" {
		return 0, errors.New("all fields are required")
	}

	switch role {

	case "MANAGER",
		"ANALYST",
		"VIEWER":

	default:
		return 0, errors.New("invalid role")
	}

	if len(password) < 8 {
		return 0, errors.New(
			"password must be at least 8 characters",
		)
	}

	// ==========================================
	// Password Hash
	// ==========================================

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)

	if err != nil {
		return 0, err
	}

	// ==========================================
	// Transaction
	// ==========================================

	tx, err := database.DB.Begin()

	if err != nil {
		return 0, err
	}

	defer tx.Rollback()

	// ==========================================
	// Create User
	// ==========================================

	result, err := tx.Exec(`
		INSERT INTO users(
			name,
			email,
			password,
			status
		)
		VALUES(?,?,?,'ACTIVE')
	`,
		name,
		email,
		string(hash),
	)

	if err != nil {
		return 0, errors.New(
			"email already registered",
		)
	}

	userID64, err := result.LastInsertId()

	if err != nil {
		return 0, err
	}

	userID := int(userID64)

	// ==========================================
	// Organization Membership
	// ==========================================

	_, err = tx.Exec(`
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

	if err != nil {
		return 0, err
	}

	// ==========================================
	// Commit
	// ==========================================

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return userID, nil
}

// ==========================================
// List Organization Users
// ==========================================

func ListUsers(
	organizationID int,
) ([]User, error) {

	rows, err := database.DB.Query(`
		SELECT
			u.id,
			u.name,
			u.email,
			ou.role,
			COALESCE(u.status, 'ACTIVE')
		FROM users u
		JOIN organization_users ou
			ON ou.user_id = u.id
		WHERE ou.organization_id=?
		ORDER BY u.id DESC
	`,
		organizationID,
	)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var result []User

	for rows.Next() {

		var user User

		if err := rows.Scan(
			&user.ID,
			&user.Name,
			&user.Email,
			&user.Role,
			&user.Status,
		); err != nil {
			return nil, err
		}

		result = append(result, user)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}
