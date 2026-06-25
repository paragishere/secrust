package website

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"secrust/internal/database"
)

func DeleteWebsite(c *gin.Context) {

	hash := c.Param("hash")

	session := sessions.Default(c)

	userID := session.Get("user_id")

	websiteID, _, err :=
		GetWebsiteByHashAndUser(
			hash,
			userID,
		)

	if err != nil {

		c.JSON(
			403,
			gin.H{
				"error": "Access denied",
			},
		)

		return
	}

	database.DB.Exec(
		"DELETE FROM logs WHERE website_id=?",
		websiteID,
	)

	database.DB.Exec(
		"DELETE FROM alerts WHERE website_id=?",
		websiteID,
	)

	database.DB.Exec(
		"DELETE FROM websites WHERE id=?",
		websiteID,
	)

	c.Redirect(
		302,
		"/websites",
	)
}
