package controllers

import (
	"net/http"

	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/initialiazers"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/models"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/utils"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func AddCredentials(c *gin.Context) {
	var body struct {
		Platform    string `json:"platform" binding:"required,min=2,max=100"`
		Description string `json:"description" binding:"required,min=2,max=100"`
		Email       string `json:"email" binding:"required,email,max=100"`
		Secret      string `json:"secret" binding:"required,min=8,max=100"`
		MasterKey   string `json:"master_key" binding:"required,min=8,max=30"`
	}

	if err := c.Bind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid input: " + err.Error(),
		})
		return
	}

	// Derive AES key from MasterKey
	key := utils.DeriveKeyFromPassword(body.MasterKey)

	// Encrypt the secret using the derived key
	encryptedSecret, err := utils.EncryptAES(body.Secret, key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to encrypt secret",
		})
		return
	}

	// Hash the MasterKey using bcrypt
	hash, err := bcrypt.GenerateFromPassword([]byte(body.MasterKey), 10)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to hash master key",
		})
		return
	}

	// Save to DB
	credential := models.Credential{
		Platform:    body.Platform,
		Description: body.Description,
		Email:       body.Email,
		Secret:      encryptedSecret,
		MasterKey:   string(hash),
	}

	if result := initialiazers.DB.Create(&credential); result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Failed to create record: " + result.Error.Error(),
		})
		return
	}

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
		Platform    string `json:"platform" binding:"omitempty,min=2,max=100"`
		Description string `json:"description" binding:"omitempty,min=2,max=100"`
		Email       string `json:"email" binding:"omitempty,email,max=100"`
		Secret      string `json:"secret" binding:"omitempty,min=8,max=30"`
		MasterKey   string `json:"master_key" binding:"omitempty,min=8,max=30"`
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
	if body.Secret != "" {
		key := utils.DeriveKeyFromPassword(body.Secret)
		encryptedPassword, err := utils.EncryptAES(body.Secret, key)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to encrypt password",
			})
			return
		}
		credential.Secret = encryptedPassword
	}
	if body.MasterKey != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(body.MasterKey), 10)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to hash password to decode",
			})
			return
		}
		credential.MasterKey = string(hash)
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
			"error": "Record not found",
		})
		return
	}

	// Delete the credential
	if err := initialiazers.DB.Delete(&credential).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete record",
		})
		return
	}

	// Return success message
	c.JSON(http.StatusOK, gin.H{
		"message": "Record deleted successfully",
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

func GetPasswordDecryptByID(c *gin.Context) {
	// Get the ID from the URL parameter
	id := c.Param("id")

	// Find the credential by ID
	var credential models.Credential
	if err := initialiazers.DB.First(&credential, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Record not found",
		})
		return
	}

	// Get the password to decode from request body
	var body struct {
		MasterKey string `json:"master_key" binding:"required"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Masterkey is required to decrypt",
		})
		return
	}

	// Compare hashed password with provided one
	err := bcrypt.CompareHashAndPassword([]byte(credential.MasterKey), []byte(body.MasterKey))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "Invalid decryption password",
		})
		return
	}

	// Decrypt password using the provided key
	decryptedPassword, err := utils.DecryptAES(credential.Secret, body.MasterKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to decrypt password",
		})
		return
	}

	// Return the decrypted password
	c.JSON(http.StatusOK, gin.H{
		"decrypted_password": decryptedPassword,
	})
}

func GetEmailByID(c *gin.Context) {
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
	c.JSON(http.StatusOK, credential.Email)

}
