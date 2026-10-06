package middleware

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func RequireRole(allowedRoles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {

		session := sessions.Default(c)

		roleValue := session.Get("role")

		if roleValue == nil {
			c.Redirect(http.StatusFound, "/login")
			c.Abort()
			return
		}

		role, ok := roleValue.(string)
		if !ok {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "Invalid role",
			})
			c.Abort()
			return
		}

		allowed := false

		for _, allowedRole := range allowedRoles {
			if role == allowedRole {
				allowed = true
				break
			}
		}

		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{
				"error": "You do not have permission to access this resource",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
