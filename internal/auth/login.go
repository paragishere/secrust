package auth

import (
	"database/sql"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"secrust/internal/database"
)

func Login(c *gin.Context) {

	email := c.PostForm("email")
	password := c.PostForm("password")

	var user User

	err := database.DB.QueryRow(
		"SELECT id,name,email,password FROM users WHERE email=?",
		email,
	).Scan(
		&user.ID,
		&user.Name,
		&user.Email,
		&user.Password,
	)

	if err == sql.ErrNoRows {

		c.JSON(
			http.StatusUnauthorized,
			gin.H{
				"error": "Invalid credentials",
			},
		)

		return
	}

	err = bcrypt.CompareHashAndPassword(
		[]byte(user.Password),
		[]byte(password),
	)

	if err != nil {

		c.JSON(
			http.StatusUnauthorized,
			gin.H{
				"error": "Invalid credentials",
			},
		)

		return
	}

	// =========================
	// Create Session
	// =========================

	session := sessions.Default(c)

	// Prevent Session Fixation
	session.Clear()

	// Store Session Data
	session.Set("user_id", user.ID)
	session.Set("user_name", user.Name)

	// Session expires after 1 hour
	session.Options(sessions.Options{
		Path:     "/",
		MaxAge:   60 * 60, // 1 Hour
		HttpOnly: true,
		Secure:   false, // Change to true when using HTTPS
	})

	if err := session.Save(); err != nil {

		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": "Failed to create session",
			},
		)

		return
	}

	// =========================
	// Redirect
	// =========================

	c.Redirect(
		302,
		"/websites",
	)
}
