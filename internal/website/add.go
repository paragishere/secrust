package website

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"secrust/internal/database"
	"secrust/internal/utils"
)

func AddWebsite(c *gin.Context) {

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
	// Form Data
	// =========================

	domain := c.PostForm("domain")

	if domain == "" {

		c.JSON(
			http.StatusBadRequest,
			gin.H{
				"error": "Domain required",
			},
		)

		return
	}

	// =========================
	// Generate Keys
	// =========================

	apiKey := GenerateAPIKey()

	hashID := utils.GenerateHash(
		domain,
	)

	// =========================
	// Save Website
	// =========================

	_, err := database.DB.Exec(
		`
		INSERT INTO websites(
			user_id,
			domain,
			hash_id,
			api_key
		)
		VALUES(?,?,?,?)
		`,
		userID,
		domain,
		hashID,
		apiKey,
	)

	if err != nil {

		c.JSON(
			http.StatusBadRequest,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	// =========================
	// Render Result
	// =========================

	// c.HTML(
	// 	200,
	// 	"add_website.html",
	// 	gin.H{
	// 		"domain":  domain,
	// 		"hash_id": hashID,
	// 		"api_key": apiKey,
	// 		"dashboard": "/website/" +
	// 			hashID +
	// 			"/dashboard",
	// 	},
	// )

	c.Redirect(
		302,
		"/website/"+hashID+"/integration",
	)
}
