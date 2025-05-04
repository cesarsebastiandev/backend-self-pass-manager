package controllers

import (
	"github.com/cesarsebastiandev/backend-self-pass-manager/initialiazers"
	"github.com/cesarsebastiandev/backend-self-pass-manager/models"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func Signup(c *gin.Context) {
	//Get the email/pass off request body

	var body struct {
		Name     string `json:"name" binding:"required,min=2,max=100"`
		Lastname string `json:"lastname" binding:"required,min=2,max=100"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
	}
	if err := c.Bind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid input: " + err.Error(),
		})
		return
	}

	//Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash the password",
		})

		return
	}

	//Insert into database and create the user

	user := models.User{Name: body.Name, Lastname: body.Lastname, Email: body.Email, Password: string(hash)}

	result := initialiazers.DB.Create(&user)

	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			// "error": "Failed to create user",
			"error": "Failed to create user: " + result.Error.Error(),
		})
		return
	}

	//Respond and return a success message
	c.JSON(http.StatusOK, gin.H{
		"message": "User created successfully",
	})
}

func Login(c *gin.Context) {
	//Get the email/pass off request body
	var body struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
	}
	if err := c.Bind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid input: " + err.Error(),
		})
		return
	}

	//Look up requested body
	var user models.User
	initialiazers.DB.First(&user, "email = ?", body.Email)
	if user.ID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})
		return
	}

	//Compare  sent in  pass with saved user pass hash
	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid email or password",
		})
		return
	}
	//Generate a jwt
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create token",
		})
		return
	}

	//Cookie config
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("token", tokenString, 30*24*30, "/", "", true, true)

	//Send it back
	c.JSON(http.StatusOK, gin.H{
		"token": "It was generated successfully",
	})
}

func Validate(c *gin.Context) {
	user, _ := c.Get("user")
	c.JSON(http.StatusOK, gin.H{
		"info":    "I'm logged in",
		"message": user,
	})

}

func Logout(c *gin.Context) {
	token, err := c.Cookie("token")
	if err != nil || token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Unauthorized",
		})
		return
	}

	// Set up the cookie with negative value to delete it
	c.SetCookie("token", "", -1, "/", "", true, true)

	c.JSON(http.StatusOK, gin.H{
		"message": "Successfully logged out",
	})
}
