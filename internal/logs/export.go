package logs

import (
	"encoding/csv"
	"strconv"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"secrust/internal/database"
	"secrust/internal/website"
)

func ExportCSV(c *gin.Context) {

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
	// Ownership Check
	// =========================

	websiteID, _, err :=
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
	// CSV Headers
	// =========================

	c.Header(
		"Content-Disposition",
		"attachment; filename=logs.csv",
	)

	c.Header(
		"Content-Type",
		"text/csv",
	)

	writer := csv.NewWriter(c.Writer)

	writer.Write([]string{
		"ID",
		"IP",
		"Method",
		"Path",
		"Status",
		"Country",
		"City",
	})

	// =========================
	// Website Logs Only
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
			city
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

	for rows.Next() {

		var id int
		var ip string
		var method string
		var path string
		var status int
		var country string
		var city string

		err := rows.Scan(
			&id,
			&ip,
			&method,
			&path,
			&status,
			&country,
			&city,
		)

		if err != nil {
			continue
		}

		writer.Write([]string{
			strconv.Itoa(id),
			ip,
			method,
			path,
			strconv.Itoa(status),
			country,
			city,
		})
	}

	writer.Flush()
}
