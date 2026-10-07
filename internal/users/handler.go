package users

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"

	"secrust/internal/database"
	"secrust/internal/invitation"
	"secrust/internal/organization"
	"secrust/internal/website"
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

	// Get pending invitations
	invitations, err := invitation.ListPending(organizationID)

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
			"invitations":  invitations,
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

// employee ke liye invite karne ka function

func AcceptInviteHandler(c *gin.Context) {

	token := c.Param("token")

	name := c.PostForm("name")
	password := c.PostForm("password")

	err := invitation.Accept(
		token,
		name,
		password,
	)

	if err != nil {
		c.HTML(http.StatusBadRequest, "invite_accept.html", gin.H{
			"error": err.Error(),
			"token": token,
			"name":  name,
		})
		return
	}

	c.Redirect(http.StatusFound, "/login")
}
func AcceptInvitePage(c *gin.Context) {

	token := c.Param("token")

	invite, err := invitation.GetByToken(token)

	if err != nil {
		c.HTML(http.StatusBadRequest, "invite_accept.html", gin.H{
			"error": err.Error(),
		})
		return
	}

	c.HTML(http.StatusOK, "invite_accept.html", gin.H{
		"token": token,
		"email": invite.Email,
		"role":  invite.Role,
	})
}
func RevokeInvitation(c *gin.Context) {

	session := sessions.Default(c)

	userID := session.Get("user_id")
	organizationID := session.Get("organization_id")

	if userID == nil || organizationID == nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	invitationID, err := strconv.Atoi(c.Param("id"))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid invitation ID",
		})
		return
	}

	orgID, ok := organizationID.(int)

	if !ok {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Invalid organization session",
		})
		return
	}

	err = invitation.Revoke(
		invitationID,
		orgID,
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.Redirect(http.StatusFound, "/users")
}
func ResendInvitation(c *gin.Context) {

	session := sessions.Default(c)

	userIDValue := session.Get("user_id")
	organizationIDValue := session.Get("organization_id")

	if userIDValue == nil || organizationIDValue == nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	userID, ok1 := userIDValue.(int)
	organizationID, ok2 := organizationIDValue.(int)

	if !ok1 || !ok2 {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Invalid session",
		})
		return
	}

	invitationID, err := strconv.Atoi(c.Param("id"))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid invitation ID",
		})
		return
	}

	token, err := invitation.Resend(
		invitationID,
		organizationID,
		userID,
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	inviteURL := "http://localhost:8080/invite/" + token

	c.HTML(http.StatusOK, "invite_created.html", gin.H{
		"invite_url": inviteURL,
	})
}
func AssignWebsitesPage(c *gin.Context) {

	session := sessions.Default(c)

	currentUserID := session.Get("user_id")
	organizationIDValue := session.Get("organization_id")

	if currentUserID == nil || organizationIDValue == nil {
		c.Redirect(http.StatusFound, "/login")
		return
	}

	organizationID, ok := organizationIDValue.(int)

	if !ok {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Invalid organization session",
		})
		return
	}

	userID, err := strconv.Atoi(c.Param("id"))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	// Make sure target user belongs to our organization.
	var name, email, role string

	err = database.DB.QueryRow(`
		SELECT
			u.name,
			u.email,
			ou.role
		FROM users u
		JOIN organization_users ou
			ON ou.user_id=u.id
		WHERE u.id=?
		AND ou.organization_id=?
	`,
		userID,
		organizationID,
	).Scan(&name, &email, &role)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "User not found",
		})
		return
	}

	websites, err := website.ListOrganizationWebsites(
		organizationID,
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	assigned, err := website.ListUserWebsiteIDs(userID)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.HTML(http.StatusOK, "assign_websites.html", gin.H{
		"user_id":  userID,
		"name":     name,
		"email":    email,
		"role":     role,
		"websites": websites,
		"assigned": assigned,
	})
}
func AssignWebsitesHandler(c *gin.Context) {

	organizationIDValue := sessions.Default(c).Get("organization_id")

	organizationID, ok := organizationIDValue.(int)

	if !ok {
		c.JSON(http.StatusForbidden, gin.H{
			"error": "Invalid organization session",
		})
		return
	}

	userID, err := strconv.Atoi(c.Param("id"))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid user ID",
		})
		return
	}

	selected := c.PostFormArray("website_ids")

	websiteIDs := make([]int, 0, len(selected))

	for _, value := range selected {

		id, err := strconv.Atoi(value)

		if err != nil {
			continue
		}

		websiteIDs = append(websiteIDs, id)
	}

	err = website.SetWebsiteAssignments(
		userID,
		organizationID,
		websiteIDs,
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.Redirect(
		http.StatusFound,
		"/users",
	)
}
