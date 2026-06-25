package middleware

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func AuthRequired(c *gin.Context) {

	session := sessions.Default(c)

	if session.Get("user_id") == nil {

		c.Redirect(302, "/login")
		c.Abort()
		return
	}

	session.Options(sessions.Options{
		Path:     "/",
		MaxAge:   60 * 60, // 1 hour from last activity
		HttpOnly: true,
		Secure:   false,
	})

	session.Save()

	c.Next()
}
