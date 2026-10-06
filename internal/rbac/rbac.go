package middleware

import (
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func RequireRole(
	allowedRoles ...string,
) gin.HandlerFunc {

	return func(c *gin.Context) {

		session := sessions.Default(c)

		role := session.Get("role")

		if role == nil {

			c.Redirect(
				http.StatusFound,
				"/login",
			)

			c.Abort()

			return
		}

		currentRole := role.(string)

		allowed := false

		for _, allowedRole := range allowedRoles {

			if currentRole == allowedRole {
				allowed = true
				break
			}
		}

		if !allowed {

			c.JSON(
				http.StatusForbidden,
				gin.H{
					"error": "Insufficient permissions",
				},
			)

			c.Abort()

			return
		}

		c.Next()
	}
}
