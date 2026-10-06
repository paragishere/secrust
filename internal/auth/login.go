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

	// =========================
	// Find User
	// =========================

	var user User

	err := database.DB.QueryRow(
		`
		SELECT
			id,
			name,
			email,
			password
		FROM users
		WHERE email=?
		`,
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

	if err != nil {

		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": "Login failed",
			},
		)

		return
	}

	// =========================
	// Verify Password
	// =========================

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
	// Get Organization
	// =========================

	var organizationID int
	var organizationName string
	var role string

	err = database.DB.QueryRow(
		`
		SELECT
			o.id,
			o.name,
			ou.role
		FROM organization_users ou
		JOIN organizations o
			ON o.id = ou.organization_id
		WHERE ou.user_id=?
		LIMIT 1
		`,
		user.ID,
	).Scan(
		&organizationID,
		&organizationName,
		&role,
	)

	if err != nil {

		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": "Organization profile not found",
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

	session.Set(
		"user_id",
		user.ID,
	)

	session.Set(
		"user_name",
		user.Name,
	)

	session.Set(
		"organization_id",
		organizationID,
	)

	session.Set(
		"organization_name",
		organizationName,
	)

	session.Set(
		"role",
		role,
	)

	// =========================
	// Session Configuration
	// =========================

	session.Options(
		sessions.Options{
			Path:     "/",
			MaxAge:   60 * 60,
			HttpOnly: true,
			Secure:   false,
		},
	)

	// =========================
	// Save Session
	// =========================

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
		http.StatusFound,
		"/websites",
	)
}
