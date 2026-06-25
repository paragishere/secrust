package alerts

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"secrust/internal/database"
	"secrust/internal/website"
)

func ListAlerts(c *gin.Context) {

	hash := c.Param("hash")

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
	// Website Ownership Check
	// =========================

	websiteID, domain, err :=
		website.GetWebsiteByHashAndUser(
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

	// =========================
	// Load Alerts
	// =========================

	rows, err := database.DB.Query(
		`
		SELECT
			id,
			severity,
			message,
			ip,
			created_at
		FROM alerts
		WHERE website_id=?
		ORDER BY id DESC
		`,
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

	defer rows.Close()

	var alerts []Alert

	for rows.Next() {

		var a Alert

		err := rows.Scan(
			&a.ID,
			&a.Severity,
			&a.Message,
			&a.IP,
			&a.CreatedAt,
		)

		if err != nil {
			continue
		}

		alerts = append(
			alerts,
			a,
		)
	}

	// =========================
	// Render
	// =========================

	c.HTML(
		200,
		"alerts.html",
		gin.H{
			"alerts": alerts,
			"hash":   hash,
			"domain": domain,
		},
	)
}
