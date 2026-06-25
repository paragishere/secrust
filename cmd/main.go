package main

import (
	"log"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"

	"secrust/internal/alerts"
	"secrust/internal/auth"
	"secrust/internal/dashboard"
	"secrust/internal/database"
	"secrust/internal/logs"
	"secrust/internal/middleware"
	"secrust/internal/realtime"
	"secrust/internal/website"
)

func main() {

	// =========================
	// Database Connection
	// =========================

	err := database.Connect()
	if err != nil {
		log.Fatal(err)
	}

	err = database.Migrate()
	if err != nil {
		log.Fatal(err)
	}

	// =========================
	// Gin
	// =========================

	r := gin.Default()

	store := cookie.NewStore(
		[]byte("Secrust-secret-key"),
	)

	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   60 * 60, // 1 hour
		HttpOnly: true,
		Secure:   false, // HTTPS hone par true
		SameSite: http.SameSiteLaxMode,
	})

	r.Use(
		sessions.Sessions(
			"Secrust-session",
			store,
		),
	)

	r.LoadHTMLGlob("templates/*")
	r.Static("/static", "./static")

	// =========================
	// Public Routes
	// =========================

	r.GET("/register", func(c *gin.Context) {
		c.HTML(200, "register.html", nil)
	})

	r.GET("/login", func(c *gin.Context) {
		c.HTML(200, "login.html", nil)
	})

	r.POST("/register", auth.Register)
	r.POST("/login", auth.Login)

	// API endpoint should remain public
	r.POST("/api/logs", logs.Ingest)

	// =========================
	// Protected Routes
	// =========================

	protected := r.Group("/")
	protected.Use(
		middleware.AuthRequired,
	)

	// Website Management

	protected.GET(
		"/websites",
		website.ListWebsites,
	)

	protected.GET(
		"/website/add",
		func(c *gin.Context) {
			c.HTML(
				200,
				"add_website.html",
				nil,
			)
		},
	)

	protected.POST(
		"/website/add",
		website.AddWebsite,
	)

	// Dashboard

	protected.GET(
		"/website/:hash/dashboard",
		dashboard.Home,
	)

	protected.GET(
		"/website/:hash/logs",
		logs.ListLogs,
	)

	protected.GET(
		"/website/:hash/logs/search",
		logs.SearchLogs,
	)

	protected.GET(
		"/website/:hash/alerts",
		alerts.ListAlerts,
	)

	protected.GET(
		"/website/:hash/export/logs",
		logs.ExportCSV,
	)

	protected.GET(
		"/website/:hash/integration",
		website.IntegrationPage,
	)
	// Realtime

	protected.GET(
		"/ws",
		realtime.HandleWS,
	)

	// Logout

	// protected.GET(
	// 	"/logout",
	// 	func(c *gin.Context) {
	// 		session := sessions.Default(c)
	// 		session.Clear()
	// 		session.Options(sessions.Options{MaxAge: -1})
	// 		session.Save()
	// 		c.Redirect(302, "/login")
	// 	},
	// )
	protected.GET(
		"/logout",
		auth.Logout,
	)

	protected.POST(
		"/website/:hash/delete",
		website.DeleteWebsite,
	)

	// Home

	r.GET("/", func(c *gin.Context) {

		session := sessions.Default(c)

		if session.Get("user_id") != nil {

			c.Redirect(
				302,
				"/websites",
			)

			return
		}

		c.HTML(
			200,
			"index.html",
			nil,
		)
	})

	protected.POST(
		"/website/:hash/apikey",
		website.RegenerateAPIKey,
	)

	// protected.GET(
	// 	"/search",
	// 	logs.SearchLogs,
	// )
	protected.GET("/dashboard", func(c *gin.Context) {
		c.Redirect(302, "/websites")
	})
	protected.GET("/website/:hash/search", logs.SearchLogs)
	// API key regeneration route removed: handler not defined in website package.
	// =========================
	// Start Server
	// =========================

	log.Println(
		"🚀 Secrust running on http://localhost:8080",
	)

	err = r.Run(":8080")
	if err != nil {
		log.Fatal(err)
	}
}
