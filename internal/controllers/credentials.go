package controllers

import (
	"net/http"

	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/initialiazers"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/models"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/utils"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/validations"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// AddCredentials godoc
// @Summary      Add new credential
// @Description  Adds a new credential with encrypted secret and hashed master key
// @Tags         Credentials
// @Accept       json
// @Produce      json
// @Param        credential  body     validations.CredentialRequest true "Credential input"
// @Success      200 {object} models.MessageResponse "Record created successfully"
// @Failure      400 {object} models.ErrorResponse "Invalid input or Failed to create record"
// @Failure      500 {object} models.ErrorResponse "Failed to encrypt secret or Failed to hash master key"
// @Router       /credentials [post]
func AddCredentials(c *gin.Context) {
	var body validations.CredentialRequest

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

// GetAllCredentials godoc
// @Summary      Return list of all credentials
// @Description  Return list of all credentials from the database
// @Tags         Credentials
// @Produce      json
// @Success      200  {array}  models.Credential
// @Failure      500  {object}  models.HTTPError
// @Router       /credentials [get]
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

// UpdateCredentialByID godoc
// @Summary      Update a credential by ID
// @Description  Update fields of an existing credential; only provided fields will be updated
// @Tags         Credentials
// @Accept       json
// @Produce      json
// @Param        id          path      int                               true  "Credential ID"
// @Param        credential  body      validations.CredentialRequest false "Fields to update"
// @Success      200 {object} models.MessageResponse "Record updated successfully"
// @Failure      400 {object} models.ErrorResponse   "Invalid input"
// @Failure      404 {object} models.ErrorResponse   "Record not found"
// @Failure      500 {object} models.ErrorResponse   "Failed to encrypt password or Failed to update record"
// @Router       /credentials/{id} [patch]
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
	var body validations.CredentialRequest
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

// DeleteCredentialByID godoc
// @Summary      Delete a credential by ID
// @Description  Deletes the credential record identified by its ID
// @Tags         Credentials
// @Produce      json
// @Param        id   path      int  true  "Credential ID"
// @Success      200  {object}  models.MessageResponse
// @Failure      404  {object}  models.ErrorResponse
// @Failure      500  {object}  models.ErrorResponse
// @Router       /credentials/{id} [delete]
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

// GetCredentialByID godoc
// @Summary      Get a credential by ID
// @Description  Retrieves a single credential record by its ID
// @Tags         Credentials
// @Produce      json
// @Param        id   path      int  true  "Credential ID"
// @Success      200  {object}  models.Credential
// @Failure      404  {object}  models.ErrorResponse
// @Router       /credentials/{id} [get]
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

// GetPasswordDecryptByID godoc
// @Summary      Decrypt password by credential ID
// @Description  Decrypts the stored secret password of a credential using the provided master key
// @Tags         Credentials
// @Accept       json
// @Produce      json
// @Param        id          path      int                  true  "Credential ID"
// @Param        master_key  body     validations.MasterKeyRequest true "Master key to decrypt the password"

// @Success      200         {object}  models.DecryptResponse
// @Failure      400         {object}  models.ErrorResponse "Masterkey is required to decrypt"
// @Failure      401         {object}  models.ErrorResponse "Invalid decryption password"
// @Failure      404         {object}  models.ErrorResponse "Record not found"
// @Failure      500         {object}  models.ErrorResponse "Failed to decrypt password"
// @Router       /credentials/decrypt/{id} [post]
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


// GetEmailByID godoc
// @Summary      Get email by credential ID
// @Description  Retrieves the email associated with a credential by its ID
// @Tags         Credentials
// @Produce      json
// @Param        id   path      int  true  "Credential ID"
// @Success      200  {object}  models.EmailResponse
// @Failure      404  {object}  models.ErrorResponse
// @Router       /credentials/email/{id} [get]

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
