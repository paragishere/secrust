package website

import (
	"errors"

	"secrust/internal/database"
)

type WebsiteAccess struct {
	WebsiteID      int
	Domain         string
	OrganizationID int
	Role           string
	Permission     string
}

// ==========================================
// Get Website Access
// ==========================================

func GetWebsiteAccess(
	hash string,
	userID interface{},
) (*WebsiteAccess, error) {

	var access WebsiteAccess

	err := database.DB.QueryRow(`
		SELECT
			w.id,
			w.domain,
			w.organization_id,
			ou.role,
			COALESCE(wu.permission, 'VIEW')
		FROM websites w

		JOIN organization_users ou
			ON ou.organization_id = w.organization_id
			AND ou.user_id = ?

		LEFT JOIN website_users wu
			ON wu.website_id = w.id
			AND wu.user_id = ?

		WHERE w.hash_id = ?
	`,
		userID,
		userID,
		hash,
	).Scan(
		&access.WebsiteID,
		&access.Domain,
		&access.OrganizationID,
		&access.Role,
		&access.Permission,
	)

	if err != nil {
		return nil, errors.New("website access denied")
	}

	return &access, nil
}
func ListOrganizationWebsites(organizationID int) ([]Website, error) {

	rows, err := database.DB.Query(`
		SELECT
			id,
			domain,
			hash_id,
			api_key
		FROM websites
		WHERE organization_id=?
		ORDER BY id DESC
	`, organizationID)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var websites []Website

	for rows.Next() {

		var w Website

		err := rows.Scan(
			&w.ID,
			&w.Domain,
			&w.HashID,
			&w.APIKey,
		)

		if err != nil {
			return nil, err
		}

		websites = append(websites, w)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return websites, nil
}
func ListUserWebsiteIDs(userID int) (map[int]bool, error) {

	rows, err := database.DB.Query(`
		SELECT website_id
		FROM website_users
		WHERE user_id=?
	`, userID)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	assigned := make(map[int]bool)

	for rows.Next() {

		var websiteID int

		if err := rows.Scan(&websiteID); err != nil {
			return nil, err
		}

		assigned[websiteID] = true
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return assigned, nil
}
func SetWebsiteAssignments(
	userID int,
	organizationID int,
	websiteIDs []int,
) error {

	// Verify that the user belongs to this organization.
	var userExists int

	err := database.DB.QueryRow(`
		SELECT 1
		FROM organization_users
		WHERE user_id=?
		AND organization_id=?
		LIMIT 1
	`,
		userID,
		organizationID,
	).Scan(&userExists)

	if err != nil {
		return errors.New("user does not belong to this organization")
	}

	tx, err := database.DB.Begin()
	if err != nil {
		return err
	}

	defer tx.Rollback()

	// Remove previous assignments.
	_, err = tx.Exec(`
		DELETE FROM website_users
		WHERE user_id=?
	`, userID)

	if err != nil {
		return err
	}

	// Add new assignments.
	for _, websiteID := range websiteIDs {

		// Make sure website belongs to the same organization.
		var websiteExists int

		err := tx.QueryRow(`
			SELECT 1
			FROM websites
			WHERE id=?
			AND organization_id=?
			LIMIT 1
		`,
			websiteID,
			organizationID,
		).Scan(&websiteExists)

		if err != nil {
			return errors.New("invalid website assignment")
		}

		_, err = tx.Exec(`
			INSERT INTO website_users(
				website_id,
				user_id,
				permission
			)
			VALUES(?,?,?)
		`,
			websiteID,
			userID,
			"VIEW",
		)

		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
