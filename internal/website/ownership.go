package website

import (
	"errors"
	"fmt"

	"secrust/internal/database"
)

func GetWebsiteByHashAndUser(
	hash string,
	userID interface{},
) (int, string, error) {

	// =========================
	// Convert Session User ID
	// =========================

	var uid int

	switch v := userID.(type) {

	case int:
		uid = v

	case int64:
		uid = int(v)

	case int32:
		uid = int(v)

	case float64:
		uid = int(v)

	default:

		fmt.Println(
			"INVALID USER ID TYPE:",
			userID,
		)

		return 0, "", errors.New(
			"invalid session",
		)
	}

	fmt.Println("HASH:", hash)
	fmt.Println("USER ID:", uid)

	// =========================
	// Website Lookup
	// =========================

	var websiteID int
	var domain string

	err := database.DB.QueryRow(
		`
		SELECT
			id,
			domain
		FROM websites
		WHERE hash_id=?
		AND user_id=?
		`,
		hash,
		uid,
	).Scan(
		&websiteID,
		&domain,
	)

	if err != nil {

		fmt.Println(
			"WEBSITE LOOKUP FAILED:",
			err,
		)

		return 0, "", errors.New(
			"website not found",
		)
	}

	fmt.Println(
		"WEBSITE FOUND:",
		websiteID,
		domain,
	)

	return websiteID, domain, nil
}
