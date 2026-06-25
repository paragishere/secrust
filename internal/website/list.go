package website

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"secrust/internal/database"
)

func ListWebsites(c *gin.Context) {

	// =========================
	// Session Check
	// =========================

	session := sessions.Default(c)

	userID := session.Get("user_id")

	if userID == nil {

		c.Redirect(
			302,
			"/login",
		)

		return
	}

	// =========================
	// Load User Websites
	// =========================

	rows, err := database.DB.Query(
		`
		SELECT
			id,
			domain,
			hash_id,
			api_key
		FROM websites
		WHERE user_id=?
		ORDER BY id DESC
		`,
		userID,
	)

	if err != nil {

		c.JSON(
			500,
			gin.H{
				"error": err.Error(),
			},
		)

		return
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
			continue
		}

		websites = append(
			websites,
			w,
		)
	}

	c.HTML(
		200,
		"websites.html",
		gin.H{
			"websites": websites,
		},
	)
}
