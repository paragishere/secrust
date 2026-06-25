package logs

import (
	"database/sql"
	"strconv"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"secrust/internal/database"
	"secrust/internal/website"
)

func SearchLogs(c *gin.Context) {

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

	query := strings.TrimSpace(
		c.Query("q"),
	)

	var rows *sql.Rows

	// =========================
	// Structured Search
	// =========================

	if strings.Contains(query, ":") {

		var conditions []string
		var args []interface{}

		conditions = append(
			conditions,
			"website_id=?",
		)

		args = append(
			args,
			websiteID,
		)

		parts := strings.Split(
			query,
			" ",
		)

		for _, part := range parts {

			if strings.HasPrefix(part, "ip:") {

				ip := strings.TrimPrefix(
					part,
					"ip:",
				)

				conditions = append(
					conditions,
					"ip LIKE ?",
				)

				args = append(
					args,
					"%"+ip+"%",
				)

			} else if strings.HasPrefix(part, "status:") {

				statusStr := strings.TrimPrefix(
					part,
					"status:",
				)

				status, _ := strconv.Atoi(
					statusStr,
				)

				conditions = append(
					conditions,
					"status=?",
				)

				args = append(
					args,
					status,
				)

			} else if strings.HasPrefix(part, "path:") {

				path := strings.TrimPrefix(
					part,
					"path:",
				)

				conditions = append(
					conditions,
					"path LIKE ?",
				)

				args = append(
					args,
					"%"+path+"%",
				)

			} else if strings.HasPrefix(part, "method:") {

				method := strings.TrimPrefix(
					part,
					"method:",
				)

				conditions = append(
					conditions,
					"method=?",
				)

				args = append(
					args,
					method,
				)
			}
		}

		sqlQuery := `
		SELECT
			id,
			ip,
			method,
			path,
			status,
			country,
			city
		FROM logs
		WHERE ` + strings.Join(
			conditions,
			" AND ",
		) + `
		ORDER BY id DESC
		`

		rows, err = database.DB.Query(
			sqlQuery,
			args...,
		)

	} else {

		rows, err = database.DB.Query(
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
			AND (
				ip LIKE ?
				OR path LIKE ?
				OR method LIKE ?
			)
			ORDER BY id DESC
			`,
			websiteID,
			"%"+query+"%",
			"%"+query+"%",
			"%"+query+"%",
		)
	}

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
		)

		if err != nil {
			continue
		}

		logs = append(
			logs,
			l,
		)
	}

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
