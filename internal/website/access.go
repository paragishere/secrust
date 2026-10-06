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
