package controllers

import (
	"net/http"
	"os"
	"time"

	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/initialiazers"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/models"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/validations"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Signup godoc
// @Summary      Register a new user
// @Description  Creates a new user with hashed password
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        user  body     validations.SignUpRequest true "User created successfully"
// @Success      200 {object} models.MessageResponse "User created successfully"
// @Failure      400 {object} models.ErrorResponse "Invalid input or Failed to create user"
// @Router       /signup [post]
func Signup(c *gin.Context) {
	//Get the email/pass off request body

	var body validations.SignUpRequest

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

// Login godoc
// @Summary      Login a user
// @Description  Authenticates a user and returns a JWT token in a secure cookie
// @Tags         Auth
// @Accept       json
// @Produce      json
// @Param        credentials  body     validations.LoginRequest true "Login credentials"
// @Success      200 {object} models.MessageResponse "Token generated successfully"
// @Failure      400 {object} models.ErrorResponse "Invalid email or password"
// @Router       /login [post]
func Login(c *gin.Context) {
	//Get the email/pass off request body
	var body validations.LoginRequest

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
		"token": "Token generated successfully",
	})
}

// Validate godoc
// @Summary      Validate authentication
// @Description  Checks if the user is authenticated and returns user info
// @Tags         Auth
// @Security     ApiKeyAuth
// @Produce      json
// @Success      200 {object} models.MessageResponse "I'm logged in"
// @Failure      401 {object} models.ErrorResponse "Unauthorized"
// @Router       /profile [get]
func Validate(c *gin.Context) {
	user, _ := c.Get("user")
	c.JSON(http.StatusOK, gin.H{
		"message": "I'm logged in",
		"info":    user,
	})

}

// Logout godoc
// @Summary      Logout a user
// @Description  Deletes the authentication token cookie to log out the user
// @Tags         Auth
// @Security     ApiKeyAuth
// @Produce      json
// @Success      200 {object} models.MessageResponse "Successfully logged out"
// @Failure      401 {object} models.ErrorResponse "Unauthorized"
// @Router       /logout [post]
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
