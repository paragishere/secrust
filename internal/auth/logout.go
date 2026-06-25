package auth

import (
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

func Logout(c *gin.Context) {

	session := sessions.Default(c)

	session.Clear()

	session.Options(sessions.Options{
		MaxAge: -1,
	})

	session.Save()

	c.Redirect(302, "/login")
}
