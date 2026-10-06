package auth

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"secrust/internal/database"
)

func Register(c *gin.Context) {

	name := strings.TrimSpace(
		c.PostForm("name"),
	)

	email := strings.ToLower(
		strings.TrimSpace(
			c.PostForm("email"),
		),
	)

	password := c.PostForm("password")

	organizationName := strings.TrimSpace(
		c.PostForm("organization"),
	)

	// ==========================================
	// Validation
	// ==========================================

	if name == "" ||
		email == "" ||
		password == "" ||
		organizationName == "" {

		c.JSON(http.StatusBadRequest, gin.H{
			"error": "All fields are required",
		})

		return
	}

	if len(password) < 8 {

		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Password must be at least 8 characters",
		})

		return
	}

	// ==========================================
	// Password Hash
	// ==========================================

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)

	if err != nil {

		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": "Failed to secure password",
			},
		)

		return
	}

	// ==========================================
	// Transaction
	// ==========================================

	tx, err := database.DB.Begin()

	if err != nil {

		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": "Failed to start registration",
			},
		)

		return
	}

	defer tx.Rollback()

	// ==========================================
	// Create User
	// ==========================================

	result, err := tx.Exec(
		`
		INSERT INTO users(
			name,
			email,
			password
		)
		VALUES(?,?,?)
		`,
		name,
		email,
		string(hash),
	)

	if err != nil {

		c.JSON(
			http.StatusBadRequest,
			gin.H{
				"error": "Email already registered or invalid data",
			},
		)

		return
	}

	userID64, err := result.LastInsertId()

	if err != nil {

		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": "Failed to create user",
			},
		)

		return
	}

	userID := int(userID64)

	// ==========================================
	// Create Organization
	// ==========================================

	result, err = tx.Exec(
		`
		INSERT INTO organizations(name)
		VALUES(?)
		`,
		organizationName,
	)

	if err != nil {

		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": "Failed to create organization",
			},
		)

		return
	}

	organizationID64, err :=
		result.LastInsertId()

	if err != nil {

		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": "Failed to create organization",
			},
		)

		return
	}

	organizationID := int(
		organizationID64,
	)

	// ==========================================
	// Add User As SUPER_ADMIN
	// ==========================================

	_, err = tx.Exec(
		`
		INSERT INTO organization_users(
			organization_id,
			user_id,
			role
		)
		VALUES(?,?,?)
		`,
		organizationID,
		userID,
		"SUPER_ADMIN",
	)

	if err != nil {

		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": "Failed to assign organization role",
			},
		)

		return
	}

	// ==========================================
	// Commit
	// ==========================================

	if err := tx.Commit(); err != nil {

		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": "Registration failed",
			},
		)

		return
	}

	// ==========================================
	// Success
	// ==========================================

	c.Redirect(
		http.StatusFound,
		"/login",
	)
}
