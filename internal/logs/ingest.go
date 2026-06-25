package logs

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"secrust/internal/alerts"
	"secrust/internal/database"
	"secrust/internal/geoip"
	"secrust/internal/realtime"
)

func Ingest(c *gin.Context) {

	var logData Log

	// =========================
	// Parse JSON
	// =========================

	if err := c.BindJSON(&logData); err != nil {

		c.JSON(
			http.StatusBadRequest,
			gin.H{
				"error": "Invalid JSON",
			},
		)

		return
	}

	println("================================")
	println("API KEY:", logData.APIKey)
	println("PATH:", logData.Path)
	println("================================")

	// =========================
	// Website Lookup
	// =========================

	var websiteID int

	err := database.DB.QueryRow(
		`
		SELECT id
		FROM websites
		WHERE api_key=?
		`,
		logData.APIKey,
	).Scan(&websiteID)

	println("WEBSITE ID:", websiteID)

	if err != nil {

		println("INVALID API KEY")

		c.JSON(
			http.StatusUnauthorized,
			gin.H{
				"error": "Invalid API Key",
			},
		)

		return
	}

	logData.WebsiteID = websiteID

	// =========================
	// Geo Location
	// =========================

	country, city :=
		geoip.Lookup(
			logData.IP,
		)

	logData.Country = country
	logData.City = city

	// =========================
	// Event Classification
	// =========================

	eventType, severity :=
		Classify(
			logData.Path,
		)

	println("EVENT TYPE:", eventType)
	println("SEVERITY:", severity)

	logData.EventType = eventType
	logData.Severity = severity

	// =========================
	// Alert Generation
	// =========================

	switch eventType {

	case "SQL_INJECTION":

		alerts.CreateAlert(
			websiteID,
			"HIGH",
			"Possible SQL Injection",
			logData.IP,
		)

	case "XSS_ATTACK":

		alerts.CreateAlert(
			websiteID,
			"HIGH",
			"Possible XSS Attack",
			logData.IP,
		)

	case "SCANNER_ACTIVITY":

		alerts.CreateAlert(
			websiteID,
			"MEDIUM",
			"Scanner Activity",
			logData.IP,
		)
	}

	// =========================
	// Store Log
	// =========================

	_, err = database.DB.Exec(
		`
		INSERT INTO logs(
			website_id,
			api_key,
			ip,
			method,
			path,
			status,
			user_agent,
			country,
			city,
			event_type,
			severity
		)
		VALUES(
			?,?,?,?,?,?,?,?,?,?,?
		)
		`,
		websiteID,
		logData.APIKey,
		logData.IP,
		logData.Method,
		logData.Path,
		logData.Status,
		logData.UserAgent,
		logData.Country,
		logData.City,
		logData.EventType,
		logData.Severity,
	)

	if err != nil {

		println("INSERT ERROR:", err.Error())

		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	println("LOG SAVED SUCCESSFULLY")

	// =========================
	// Brute Force Detection
	// =========================

	var count int

	err = database.DB.QueryRow(
		`
		SELECT COUNT(*)
		FROM logs
		WHERE website_id=?
		AND ip=?
		AND path='/login'
		`,
		websiteID,
		logData.IP,
	).Scan(&count)

	if err == nil && count >= 5 {

		alerts.CreateAlert(
			websiteID,
			"HIGH",
			"Possible Brute Force Attack",
			logData.IP,
		)
	}

	// =========================
	// Realtime
	// =========================

	println("BROADCASTING EVENT")

	realtime.Broadcast(
		logData,
	)

	// =========================
	// Response
	// =========================

	c.JSON(
		http.StatusOK,
		gin.H{
			"message":    "Log Stored",
			"website":    websiteID,
			"country":    logData.Country,
			"city":       logData.City,
			"event_type": logData.EventType,
			"severity":   logData.Severity,
		},
	)
}
