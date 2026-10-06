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
