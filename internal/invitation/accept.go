package invitation

import (
	"errors"
	"strings"

	"secrust/internal/database"

	"golang.org/x/crypto/bcrypt"
)

type InviteDetails struct {
	ID             int
	OrganizationID int
	Email          string
	Role           string
}

func GetByToken(token string) (*InviteDetails, error) {

	tokenHash := hashToken(token)

	var invite InviteDetails

	err := database.DB.QueryRow(`
		SELECT
			id,
			organization_id,
			email,
			role
		FROM invitations
		WHERE token_hash=?
		AND accepted_at IS NULL
		AND expires_at > CURRENT_TIMESTAMP
	`,
		tokenHash,
	).Scan(
		&invite.ID,
		&invite.OrganizationID,
		&invite.Email,
		&invite.Role,
	)

	if err != nil {
		return nil, errors.New("invitation is invalid or expired")
	}

	return &invite, nil
}

func Accept(
	token string,
	name string,
	password string,
) error {

	name = strings.TrimSpace(name)

	if name == "" {
		return errors.New("name is required")
	}

	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	invite, err := GetByToken(token)
	if err != nil {
		return err
	}

	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)

	if err != nil {
		return errors.New("unable to secure password")
	}

	tx, err := database.DB.Begin()
	if err != nil {
		return errors.New("unable to start account creation")
	}

	defer tx.Rollback()

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
		invite.Email,
		string(passwordHash),
	)

	if err != nil {
		return errors.New("unable to create user")
	}

	userID, err := result.LastInsertId()
	if err != nil {
		return errors.New("unable to create user")
	}

	_, err = tx.Exec(`
		INSERT INTO organization_users(
			organization_id,
			user_id,
			role
		)
		VALUES(?,?,?)
	`,
		invite.OrganizationID,
		userID,
		invite.Role,
	)

	if err != nil {
		return errors.New("unable to assign organization role")
	}

	_, err = tx.Exec(`
		UPDATE invitations
		SET accepted_at=CURRENT_TIMESTAMP
		WHERE id=?
	`,
		invite.ID,
	)

	if err != nil {
		return errors.New("unable to complete invitation")
	}

	if err := tx.Commit(); err != nil {
		return errors.New("unable to complete account creation")
	}

	return nil
}
