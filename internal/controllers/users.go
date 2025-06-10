package controllers

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/initialiazers"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/models"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/validations"
	"go.mongodb.org/mongo-driver/bson"

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
	//Get the all data off request body

	var body validations.SignUpRequest

	if err := c.Bind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}
	//Hash the password
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash the password"})
		return
	}
	//Insert into database and create the user
	user := models.User{
		Name:      body.Name,
		Lastname:  body.Lastname,
		Email:     body.Email,
		Password:  string(hash),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Check if user already exists
	count, err := initialiazers.UserCollection.CountDocuments(ctx, bson.M{"email": user.Email})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Database error"})
		return
	}
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User already exists"})
		return
	}

	_, err = initialiazers.UserCollection.InsertOne(ctx, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User created successfully"})
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
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input: " + err.Error()})
		return
	}
	//Look up requested body
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var user models.User
	err := initialiazers.UserCollection.FindOne(ctx, bson.M{"email": body.Email}).Decode(&user)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email or password"})
		return
	}

	//Compare  sent in  pass with saved user pass hash
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email or password"})
		return
	}

	// Generate JWT
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID.Hex(),
		"exp": time.Now().Add(30 * 24 * time.Hour).Unix(),
	})

	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString([]byte(os.Getenv("SECRET")))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
		return
	}
	//Cookie config
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("token", tokenString, 30*24*60*60, "/", "", true, true)

	c.JSON(http.StatusOK, gin.H{"token": "Token generated successfully"})
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
