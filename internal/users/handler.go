package users

import (
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"secrust/internal/invitation"
	"secrust/internal/organization"
)

// ==========================================
// Users Page
// ==========================================

func ListUsersPage(c *gin.Context) {

	session := sessions.Default(c)

	userID := session.Get("user_id")

	if userID == nil {
		c.Redirect(
			http.StatusFound,
			"/login",
		)
		return
	}

	organizationID, organizationName, role, err :=
		organization.GetUserOrganization(userID)

	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": "Organization not found",
			},
		)
		return
	}

	users, err := ListUsers(organizationID)

	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": err.Error(),
			},
		)
		return
	}

	c.HTML(
		http.StatusOK,
		"users.html",
		gin.H{
			"users":        users,
			"organization": organizationName,
			"current_role": role,
		},
	)
}

// ==========================================
// Add User Page
// ==========================================

func AddUserPage(c *gin.Context) {

	session := sessions.Default(c)

	userID := session.Get("user_id")

	if userID == nil {
		c.Redirect(
			http.StatusFound,
			"/login",
		)
		return
	}

	c.HTML(
		http.StatusOK,
		"add_user.html",
		nil,
	)
}

// ==========================================
// Create User Handler
// ==========================================

func CreateUserHandler(c *gin.Context) {

	session := sessions.Default(c)

	userID := session.Get("user_id")

	if userID == nil {
		c.Redirect(
			http.StatusFound,
			"/login",
		)
		return
	}

	organizationID, _, _, err :=
		organization.GetUserOrganization(userID)

	if err != nil {
		c.JSON(
			http.StatusInternalServerError,
			gin.H{
				"error": "Organization not found",
			},
		)
		return
	}

	name := strings.TrimSpace(
		c.PostForm("name"),
	)

	email := strings.TrimSpace(
		c.PostForm("email"),
	)

	password := c.PostForm("password")

	role := strings.ToUpper(
		strings.TrimSpace(
			c.PostForm("role"),
		),
	)

	_, err = CreateUser(
		name,
		email,
		password,
		role,
		organizationID,
	)

	if err != nil {

		c.HTML(
			http.StatusBadRequest,
			"add_user.html",
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	c.Redirect(
		http.StatusFound,
		"/users",
	)
}
func InviteUserPage(c *gin.Context) {

	c.HTML(http.StatusOK, "invite_user.html", nil)
}
func InviteUserHandler(c *gin.Context) {

	session := sessions.Default(c)

	userIDValue := session.Get("user_id")
	organizationIDValue := session.Get("organization_id")
	roleValue := session.Get("role")

	if userIDValue == nil ||
		organizationIDValue == nil ||
		roleValue == nil {

		c.Redirect(http.StatusFound, "/login")
		return
	}

	userID, ok1 := userIDValue.(int)
	organizationID, ok2 := organizationIDValue.(int)
	currentRole, ok3 := roleValue.(string)

	if !ok1 || !ok2 || !ok3 {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Invalid session",
		})
		return
	}

	if currentRole != "SUPER_ADMIN" &&
		currentRole != "MANAGER" {

		c.JSON(http.StatusForbidden, gin.H{
			"error": "You do not have permission to invite users",
		})
		return
	}

	email := strings.TrimSpace(c.PostForm("email"))
	role := strings.ToUpper(strings.TrimSpace(c.PostForm("role")))

	token, err := invitation.Create(
		organizationID,
		email,
		role,
		userID,
	)

	if err != nil {
		c.HTML(http.StatusBadRequest, "invite_user.html", gin.H{
			"error": err.Error(),
		})
		return
	}

	inviteURL := "http://localhost:8080/invite/" + token

	c.HTML(http.StatusOK, "invite_created.html", gin.H{
		"email":      email,
		"role":       role,
		"invite_url": inviteURL,
	})
}
