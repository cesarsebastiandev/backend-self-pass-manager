package controllers

import (
	"context"
	"net/http"
	"time"

	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/initialiazers"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/models"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/utils"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/validations"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

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

	// Build the credential model
	credential := models.Credential{
		Platform:    body.Platform,
		Description: body.Description,
		Email:       body.Email,
		Secret:      encryptedSecret,
		MasterKey:   string(hash),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Save to MongoDB
	_, err = initialiazers.CredentialCollection.InsertOne(context.TODO(), credential)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create record: " + err.Error(),
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

	// Find all credentials in MongoDB
	cursor, err := initialiazers.CredentialCollection.Find(context.TODO(), bson.M{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to retrieve records: " + err.Error(),
		})
		return
	}
	defer cursor.Close(context.TODO())

	// Iterate over cursor and decode each document into a Credential
	for cursor.Next(context.TODO()) {
		var credential models.Credential
		if err := cursor.Decode(&credential); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Error decoding credential: " + err.Error(),
			})
			return
		}
		credentials = append(credentials, credential)
	}

	// Check if no records found
	if len(credentials) == 0 {
		c.JSON(http.StatusOK, gin.H{
			"message": "No records found",
		})
		return
	}

	// Return the credentials
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
	idParam := c.Param("id")
	objectID, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}

	// Find the existing credential
	var existingCredential models.Credential
	err = initialiazers.CredentialCollection.FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&existingCredential)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record not found"})
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

	// Prepare fields to update
	updateFields := bson.M{}
	if body.Platform != "" {
		updateFields["platform"] = body.Platform
	}
	if body.Description != "" {
		updateFields["description"] = body.Description
	}
	if body.Email != "" {
		updateFields["email"] = body.Email
	}
	if body.Secret != "" {
		key := utils.DeriveKeyFromPassword(body.MasterKey)
		encryptedPassword, err := utils.EncryptAES(body.Secret, key)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to encrypt password",
			})
			return
		}
		updateFields["secret"] = encryptedPassword
	}
	if body.MasterKey != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(body.MasterKey), 10)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to hash master key",
			})
			return
		}
		updateFields["master_key"] = string(hash)
	}

	// Always update UpdatedAt timestamp
	updateFields["updated_at"] = time.Now()

	// Perform the update
	_, err = initialiazers.CredentialCollection.UpdateOne(
		context.TODO(),
		bson.M{"_id": objectID},
		bson.M{"$set": updateFields},
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to update record: " + err.Error(),
		})
		return
	}

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
	idParam := c.Param("id")

	// Convert string ID to ObjectID
	objectID, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid ID format",
		})
		return
	}

	// Attempt to delete the credential
	result, err := initialiazers.CredentialCollection.DeleteOne(context.TODO(), bson.M{"_id": objectID})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete record: " + err.Error(),
		})
		return
	}

	// If no documents were deleted
	if result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Record not found",
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
	idParam := c.Param("id")

	// Convert string ID to MongoDB ObjectID
	objectID, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid ID format",
		})
		return
	}

	// Find the credential in MongoDB
	var credential models.Credential
	err = initialiazers.CredentialCollection.FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&credential)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Record not found",
		})
		return
	}

	// Return the found credential
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
	idParam := c.Param("id")

	objectID, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}

	// Crear contexto con timeout de 10 segundos
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var credential models.Credential
	err = initialiazers.CredentialCollection.FindOne(ctx, bson.M{"_id": objectID}).Decode(&credential)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record not found"})
		return
	}

	var body struct {
		MasterKey string `json:"master_key" binding:"required"`
	}
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "MasterKey is required to decrypt"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(credential.MasterKey), []byte(body.MasterKey))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid decryption password"})
		return
	}

	decryptedPassword, err := utils.DecryptAES(credential.Secret, body.MasterKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decrypt password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"decrypted_password": decryptedPassword})
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
	idParam := c.Param("id")

	objectID, err := primitive.ObjectIDFromHex(idParam)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
		return
	}

	var credential models.Credential

	err = initialiazers.CredentialCollection.FindOne(context.TODO(), bson.M{"_id": objectID}).Decode(&credential)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Record not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"email": credential.Email})
}

// func GetEmailByID(c *gin.Context) {
// 	// Get the ID from the URL parameter
// 	idParam := c.Param("id")

// 	// Convert string to ObjectID
// 	objectID, err := primitive.ObjectIDFromHex(idParam)
// 	if err != nil {
// 		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID format"})
// 		return
// 	}

// 	// Use projection to get only email field
// 	projection := options.FindOne().SetProjection(bson.M{"email": 1})

// 	var result struct {
// 		Email string `bson:"email" json:"email"`
// 	}

// 	err = initialiazers.CredentialCollection.
// 		FindOne(context.TODO(), bson.M{"_id": objectID}, projection).
// 		Decode(&result)

// 	if err != nil {
// 		c.JSON(http.StatusNotFound, gin.H{"error": "Record not found"})
// 		return
// 	}

// 	c.JSON(http.StatusOK, gin.H{"email": result.Email})
// }
