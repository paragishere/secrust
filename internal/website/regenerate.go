package website

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"secrust/internal/database"
)

func RegenerateAPIKey(c *gin.Context) {

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

	// Ownership Check

	websiteID, _, err :=
		GetWebsiteByHashAndUser(
			hash,
			userID,
		)

	if err != nil {

		c.JSON(
			http.StatusForbidden,
			gin.H{
				"error": "Access denied",
			},
		)

		return
	}

	// Generate New Key

	newKey := GenerateAPIKey()

	// Update Database

	_, err = database.DB.Exec(
		`
		UPDATE websites
		SET api_key=?
		WHERE id=?
		`,
		newKey,
		websiteID,
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

	c.Redirect(
		302,
		"/websites",
	)
}
