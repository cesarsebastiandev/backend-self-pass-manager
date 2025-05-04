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

func GetAllCredentials(c *gin.Context) {
	var credentials []models.Credential

	// Retrieve all records
	result := initialiazers.DB.Find(&credentials)

	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve records: " + result.Error.Error(),
		})
		return
	}

	if len(credentials) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"message": "No records found",
		})
		return
	}

	// c.JSON(http.StatusOK, gin.H{
	// 	"data": credentials,
	// })
	c.JSON(http.StatusOK, credentials)
}

func UpdateCredentialByID(c *gin.Context) {
	// Get the ID from the URL
	id := c.Param("id")

	// Find the existing credential
	var credential models.Credential
	if err := initialiazers.DB.First(&credential, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Record not found",
		})
		return
	}

	// Bind the new data from the request body
	var body struct {
		Platform         string `json:"platform" binding:"omitempty,min=2,max=100"`
		Description      string `json:"description" binding:"omitempty,min=2,max=100"`
		Email            string `json:"email" binding:"omitempty,email,max=100"`
		Password         string `json:"password" binding:"omitempty,min=8,max=30"`
		PasswordToDecode string `json:"password_to_decode" binding:"omitempty,min=8,max=30"`
	}
	if err := c.Bind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid input: " + err.Error(),
		})
		return
	}

	// Update fields if present
	if body.Platform != "" {
		credential.Platform = body.Platform
	}
	if body.Description != "" {
		credential.Description = body.Description
	}
	if body.Email != "" {
		credential.Email = body.Email
	}
	if body.Password != "" {
		key := utils.DeriveKeyFromPassword(body.Password)
		encryptedPassword, err := utils.EncryptAES(body.Password, key)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to encrypt password",
			})
			return
		}
		credential.Password = encryptedPassword
	}
	if body.PasswordToDecode != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(body.PasswordToDecode), 10)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to hash password to decode",
			})
			return
		}
		credential.PasswordToDecode = string(hash)
	}

	// Save the updated credential
	if err := initialiazers.DB.Save(&credential).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update record: " + err.Error(),
		})
		return
	}

	// Return the updated record
	c.JSON(http.StatusOK, gin.H{
		"message": "Record updated successfully",
	})
}

func DeleteCredentialByID(c *gin.Context) {
	// Get the ID from the URL parameter
	id := c.Param("id")

	// Check if the credential exists
	var credential models.Credential
	if err := initialiazers.DB.First(&credential, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Credential not found",
		})
		return
	}

	// Delete the credential
	if err := initialiazers.DB.Delete(&credential).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete credential",
		})
		return
	}

	// Return success message
	c.JSON(http.StatusOK, gin.H{
		"message": "Credential deleted successfully",
	})
}

func GetCredentialByID(c *gin.Context) {
	// Get the ID from the URL parameter
	id := c.Param("id")

	// Check if the credential exists
	var credential models.Credential
	if err := initialiazers.DB.First(&credential, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Record not found",
		})
		return
	}
	c.JSON(http.StatusOK, credential)

}
