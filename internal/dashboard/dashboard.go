package dashboard

import (
	"secrust/internal/database"
	"secrust/internal/website"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

type RecentLog struct {
	IP     string
	Path   string
	Status int
	Time   string
}

type TopIPStat struct {
	IP    string
	Count int
}

func Home(c *gin.Context) {

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
	// Dashboard Counters
	// =========================

	var logsCount int
	var alertsCount int

	database.DB.QueryRow(
		`
		SELECT COUNT(*)
		FROM logs
		WHERE website_id=?
		`,
		websiteID,
	).Scan(&logsCount)

	database.DB.QueryRow(
		`
		SELECT COUNT(*)
		FROM alerts
		WHERE website_id=?
		`,
		websiteID,
	).Scan(&alertsCount)

	// =========================
	// Status Analytics
	// =========================

	var success200 int
	var error404 int
	var error500 int

	database.DB.QueryRow(
		`
		SELECT COUNT(*)
		FROM logs
		WHERE website_id=?
		AND status=200
		`,
		websiteID,
	).Scan(&success200)

	database.DB.QueryRow(
		`
		SELECT COUNT(*)
		FROM logs
		WHERE website_id=?
		AND status=404
		`,
		websiteID,
	).Scan(&error404)

	database.DB.QueryRow(
		`
		SELECT COUNT(*)
		FROM logs
		WHERE website_id=?
		AND status=500
		`,
		websiteID,
	).Scan(&error500)

	// =========================
	// Top Attacker IPs
	// =========================

	rows2, err := database.DB.Query(
		`
		SELECT
			ip,
			COUNT(*) as total
		FROM logs
		WHERE website_id=?
		GROUP BY ip
		ORDER BY total DESC
		LIMIT 5
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

	defer rows2.Close()

	var topIPs []TopIPStat

	for rows2.Next() {

		var ip TopIPStat

		err := rows2.Scan(
			&ip.IP,
			&ip.Count,
		)

		if err != nil {
			continue
		}

		topIPs = append(
			topIPs,
			ip,
		)
	}

	// =========================
	// Recent Logs
	// =========================

	rows, err := database.DB.Query(
		`
		SELECT
			ip,
			path,
			status,
			created_at
		FROM logs
		WHERE website_id=?
		ORDER BY id DESC
		LIMIT 10
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

	var recentLogs []RecentLog

	for rows.Next() {

		var log RecentLog

		err := rows.Scan(
			&log.IP,
			&log.Path,
			&log.Status,
			&log.Time,
		)

		if err != nil {
			continue
		}

		recentLogs = append(
			recentLogs,
			log,
		)
	}

	// =========================
	// Render Dashboard
	// =========================

	c.HTML(
		200,
		"dashboard.html",
		gin.H{
			"domain": domain,
			"hash":   hash,

			"logs":   logsCount,
			"alerts": alertsCount,

			"ok200":  success200,
			"err404": error404,
			"err500": error500,

			"recent": recentLogs,
			"topips": topIPs,
		},
	)
}
