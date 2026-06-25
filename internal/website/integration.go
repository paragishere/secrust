package website

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"secrust/internal/database"
)

func IntegrationPage(c *gin.Context) {

	hash := c.Param("hash")

	session := sessions.Default(c)

	userID := session.Get("user_id")

	if userID == nil {

		c.Redirect(
			302,
			"/login",
		)

		return
	}

	var website Website

	err := database.DB.QueryRow(
		`
		SELECT
			id,
			domain,
			api_key,
			hash_id
		FROM websites
		WHERE hash_id=?
		AND user_id=?
		`,
		hash,
		userID,
	).Scan(
		&website.ID,
		&website.Domain,
		&website.APIKey,
		&website.HashID,
	)

	if err != nil {

		c.JSON(
			404,
			gin.H{
				"error": "Website not found",
			},
		)

		return
	}

	c.HTML(
		200,
		"integration.html",
		gin.H{
			"website": website,
		},
	)
}
