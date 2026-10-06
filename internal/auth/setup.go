package auth

import (
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"secrust/internal/database"
)

func SetupPage(c *gin.Context) {

	var count int

	err := database.DB.QueryRow(
		`SELECT COUNT(*) FROM organizations`,
	).Scan(&count)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Unable to check setup status",
		})
		return
	}

	// Already initialized
	if count > 0 {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	c.HTML(http.StatusOK, "setup.html", nil)
}

func SetupOrganization(c *gin.Context) {

	var count int

	err := database.DB.QueryRow(
		`SELECT COUNT(*) FROM organizations`,
	).Scan(&count)

	if err != nil {
		c.JSON(500, gin.H{
			"error": "Unable to check setup status",
		})
		return
	}

	// Prevent creating another organization through setup
	if count > 0 {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	name := strings.TrimSpace(c.PostForm("name"))
	email := strings.ToLower(strings.TrimSpace(c.PostForm("email")))
	password := c.PostForm("password")
	organizationName := strings.TrimSpace(c.PostForm("organization"))

	if name == "" ||
		email == "" ||
		password == "" ||
		organizationName == "" {

		c.JSON(400, gin.H{
			"error": "All fields are required",
		})
		return
	}

	if len(password) < 8 {
		c.JSON(400, gin.H{
			"error": "Password must be at least 8 characters",
		})
		return
	}

	passwordHash, err := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)

	if err != nil {
		c.JSON(500, gin.H{
			"error": "Unable to secure password",
		})
		return
	}

	tx, err := database.DB.Begin()
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Unable to start setup",
		})
		return
	}

	defer tx.Rollback()

	// Create admin user
	result, err := tx.Exec(`
		INSERT INTO users(name,email,password,status)
		VALUES(?,?,?,'ACTIVE')
	`, name, email, string(passwordHash))

	if err != nil {
		c.JSON(400, gin.H{
			"error": "Unable to create administrator",
		})
		return
	}

	userID, err := result.LastInsertId()
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Unable to create administrator",
		})
		return
	}

	// Create organization
	result, err = tx.Exec(`
		INSERT INTO organizations(name)
		VALUES(?)
	`, organizationName)

	if err != nil {
		c.JSON(500, gin.H{
			"error": "Unable to create organization",
		})
		return
	}

	organizationID, err := result.LastInsertId()
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Unable to create organization",
		})
		return
	}

	// Make user SUPER_ADMIN
	_, err = tx.Exec(`
		INSERT INTO organization_users(
			organization_id,
			user_id,
			role
		)
		VALUES(?,?,?)
	`, organizationID, userID, "SUPER_ADMIN")

	if err != nil {
		c.JSON(500, gin.H{
			"error": "Unable to assign administrator role",
		})
		return
	}

	if err := tx.Commit(); err != nil {
		c.JSON(500, gin.H{
			"error": "Unable to complete setup",
		})
		return
	}

	// Automatically login the new Super Admin
	session := sessions.Default(c)

	session.Clear()

	session.Set("user_id", int(userID))
	session.Set("user_name", name)
	session.Set("organization_id", int(organizationID))
	session.Set("organization_name", organizationName)
	session.Set("role", "SUPER_ADMIN")

	if err := session.Save(); err != nil {
		c.JSON(500, gin.H{
			"error": "Organization created but login session failed",
		})
		return
	}

	c.Redirect(http.StatusFound, "/websites")
}
