package website

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"secrust/internal/database"
)

func ListWebsites(c *gin.Context) {

	session := sessions.Default(c)

	userIDValue := session.Get("user_id")
	organizationIDValue := session.Get("organization_id")
	roleValue := session.Get("role")

	if userIDValue == nil ||
		organizationIDValue == nil ||
		roleValue == nil {

		c.Redirect(http.StatusFound, "/login")
		return
	}

	userID, ok := userIDValue.(int)
	if !ok {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Invalid user session",
		})
		return
	}

	organizationID, ok := organizationIDValue.(int)
	if !ok {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Invalid organization session",
		})
		return
	}

	role, ok := roleValue.(string)
	if !ok {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Invalid role session",
		})
		return
	}

	var rowsQuery string
	var args []interface{}

	// =========================
	// Organization Management
	// =========================

	if role == "SUPER_ADMIN" || role == "MANAGER" {

		rowsQuery = `
			SELECT
				id,
				domain,
				hash_id,
				api_key
			FROM websites
			WHERE organization_id=?
			ORDER BY id DESC
		`

		args = []interface{}{
			organizationID,
		}

	} else {

		// =========================
		// Assigned Websites Only
		// =========================

		rowsQuery = `
			SELECT
				w.id,
				w.domain,
				w.hash_id,
				w.api_key
			FROM websites w
			INNER JOIN website_users wu
				ON wu.website_id = w.id
			WHERE w.organization_id=?
			AND wu.user_id=?
			ORDER BY w.id DESC
		`

		args = []interface{}{
			organizationID,
			userID,
		}
	}

	rows, err := database.DB.Query(
		rowsQuery,
		args...,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
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
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": err.Error(),
			})
			return
		}

		websites = append(websites, w)
	}

	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.HTML(
		http.StatusOK,
		"websites.html",
		gin.H{
			"websites": websites,
			"role":     role,
		},
	)
}
