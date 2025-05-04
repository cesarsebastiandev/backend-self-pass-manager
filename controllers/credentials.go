package controllers

import (
	"net/http"

	"github.com/cesarsebastiandev/backend-self-pass-manager/initialiazers"
	"github.com/cesarsebastiandev/backend-self-pass-manager/models"
	"github.com/cesarsebastiandev/backend-self-pass-manager/utils"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func AddCredentials(c *gin.Context) {
	//Get the email/pass off request body

	var body struct {
		Platform         string `json:"platform" binding:"required,min=2,max=100"`
		Description      string `json:"description" binding:"required,min=2,max=100"`
		Email            string `json:"email" binding:"required,email,max=100"`
		Password         string `json:"password" binding:"required,min=8,max=30"`
		PasswordToDecode string `json:"password_to_decode" binding:"required,min=8,max=30"`
	}
	if err := c.Bind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid input: " + err.Error(),
		})
		return
	}

	// Derive the 32-byte key from the user's password
	key := utils.DeriveKeyFromPassword(body.Password)

	//Encrypt the password
	encryptedPassword, err := utils.EncryptAES(body.Password, key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to encrypt password",
		})
		return
	}

	//Hash the password to decode
	hash, err := bcrypt.GenerateFromPassword([]byte(body.PasswordToDecode), 10)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to hash the password for decoding",
		})

		return
	}

	//Insert into database and create the user

	user := models.Credential{Platform: body.Platform, Description: body.Description, Email: body.Email, Password: encryptedPassword, PasswordToDecode: string(hash)}

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
		"message": "Record created successfully",
	})
}
