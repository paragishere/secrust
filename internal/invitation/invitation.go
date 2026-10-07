package invitation

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"secrust/internal/database"
)

type Invitation struct {
	ID             int
	OrganizationID int
	Email          string
	Role           string
	TokenHash      string
	InvitedBy      int
	ExpiresAt      string
	AcceptedAt     *string
	CreatedAt      string
}

func generateToken() (string, error) {
	b := make([]byte, 32)

	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	return hex.EncodeToString(b), nil
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func Create(
	organizationID int,
	email string,
	role string,
	invitedBy int,
) (string, error) {

	email = strings.ToLower(strings.TrimSpace(email))
	role = strings.ToUpper(strings.TrimSpace(role))

	if email == "" {
		return "", errors.New("email is required")
	}

	switch role {
	case "MANAGER", "ANALYST", "VIEWER":
	default:
		return "", errors.New("invalid invitation role")
	}

	// Check if user already exists
	var existingUser int

	err := database.DB.QueryRow(
		`SELECT id FROM users WHERE email=?`,
		email,
	).Scan(&existingUser)

	if err == nil {
		return "", errors.New("user already exists")
	}

	token, err := generateToken()
	if err != nil {
		return "", errors.New("unable to generate invitation token")
	}

	tokenHash := hashToken(token)

	expiresAt := time.Now().Add(24 * time.Hour)

	// Remove previous pending invitation
	_, _ = database.DB.Exec(`
		DELETE FROM invitations
		WHERE organization_id=?
		AND email=?
		AND accepted_at IS NULL
	`, organizationID, email)

	_, err = database.DB.Exec(`
		INSERT INTO invitations(
			organization_id,
			email,
			role,
			token_hash,
			invited_by,
			expires_at
		)
		VALUES(?,?,?,?,?,?)
	`,
		organizationID,
		email,
		role,
		tokenHash,
		invitedBy,
		expiresAt,
	)

	if err != nil {
		return "", err
	}

	return token, nil
}

// for the satus of the invitation
func ListPending(organizationID int) ([]Invitation, error) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			organization_id,
			email,
			role,
			token_hash,
			invited_by,
			expires_at,
			accepted_at,
			created_at
		FROM invitations
		WHERE organization_id=?
		AND accepted_at IS NULL
		AND expires_at > CURRENT_TIMESTAMP
		ORDER BY id DESC
	`, organizationID)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var invitations []Invitation

	for rows.Next() {

		var invite Invitation

		err := rows.Scan(
			&invite.ID,
			&invite.OrganizationID,
			&invite.Email,
			&invite.Role,
			&invite.TokenHash,
			&invite.InvitedBy,
			&invite.ExpiresAt,
			&invite.AcceptedAt,
			&invite.CreatedAt,
		)

		if err != nil {
			return nil, err
		}

		invitations = append(invitations, invite)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return invitations, nil
}

func Revoke(invitationID int, organizationID int) error {

	result, err := database.DB.Exec(`
		DELETE FROM invitations
		WHERE id=?
		AND organization_id=?
		AND accepted_at IS NULL
	`,
		invitationID,
		organizationID,
	)

	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return errors.New("invitation not found")
	}

	return nil
}
func Resend(invitationID int, organizationID int, invitedBy int) (string, error) {

	var email, role string

	err := database.DB.QueryRow(`
		SELECT email, role
		FROM invitations
		WHERE id=?
		AND organization_id=?
		AND accepted_at IS NULL
	`,
		invitationID,
		organizationID,
	).Scan(&email, &role)

	if err != nil {
		return "", errors.New("invitation not found")
	}

	token, err := generateToken()
	if err != nil {
		return "", errors.New("unable to generate invitation token")
	}

	tokenHash := hashToken(token)

	expiresAt := time.Now().Add(24 * time.Hour)

	_, err = database.DB.Exec(`
		UPDATE invitations
		SET token_hash=?,
		    expires_at=?,
		    invited_by=?,
		    created_at=CURRENT_TIMESTAMP
		WHERE id=?
		AND organization_id=?
		AND accepted_at IS NULL
	`,
		tokenHash,
		expiresAt,
		invitedBy,
		invitationID,
		organizationID,
	)

	if err != nil {
		return "", err
	}

	return token, nil
}
