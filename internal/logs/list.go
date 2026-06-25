package logs

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"secrust/internal/database"
	"secrust/internal/website"
)

func ListLogs(c *gin.Context) {

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
	// Load Logs
	// =========================

	rows, err := database.DB.Query(
		`
	SELECT
		id,
		ip,
		method,
		path,
		status,
		country,
		city,
		event_type,
		severity,
		created_at
	FROM logs
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

	var logs []Log

	for rows.Next() {

		var l Log

		err := rows.Scan(
			&l.ID,
			&l.IP,
			&l.Method,
			&l.Path,
			&l.Status,
			&l.Country,
			&l.City,
			&l.EventType,
			&l.Severity,
			&l.CreatedAt,
		)

		if err != nil {

			println("SCAN ERROR:", err.Error())

			continue
		}

		logs = append(
			logs,
			l,
		)
	}

	// =========================
	// Render
	// =========================

	c.HTML(
		200,
		"logs.html",
		gin.H{
			"logs":   logs,
			"hash":   hash,
			"domain": domain,
		},
	)
}
