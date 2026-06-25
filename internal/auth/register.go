package auth

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"secrust/internal/database"
)

func Register(c *gin.Context) {

	name := c.PostForm("name")
	email := c.PostForm("email")
	password := c.PostForm("password")

	hash, _ := bcrypt.GenerateFromPassword(
		[]byte(password),
		bcrypt.DefaultCost,
	)

	_, err := database.DB.Exec(
		"INSERT INTO users(name,email,password) VALUES(?,?,?)",
		name,
		email,
		string(hash),
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.Redirect(
		302,
		"/login",
	)
}
