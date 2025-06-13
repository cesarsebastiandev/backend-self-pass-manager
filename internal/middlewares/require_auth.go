package middlewares

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/initialiazers"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"github.com/golang-jwt/jwt/v5"

	"github.com/gin-gonic/gin"
)

func RequireAuth(c *gin.Context) {
	fmt.Println("In middleware")

	// Get the cookie off request
	tokenString, err := c.Cookie("token")
	if err != nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token not found in cookies"})
		return
	}

	// Decode/validate it
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte(os.Getenv("SECRET")), nil
	})

	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or missing token"})
		return
	}

	// Extract claims
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		// Check the expiration
		if float64(time.Now().Unix()) > claims["exp"].(float64) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			return
		}

		// Find the user with the token "sub" claim
		userIDHex, ok := claims["sub"].(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID format in token"})
			return
		}

		userID, err := primitive.ObjectIDFromHex(userIDHex)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid ObjectID"})
			return
		}

		var user models.User
		err = initialiazers.UserCollection.FindOne(context.TODO(), bson.M{"_id": userID}).Decode(&user)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
			return
		}

		// Attach user to request context
		c.Set("user", user)

		// Continue to next handler
		c.Next()
	} else {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Something went wrong, try again..."})
	}
}
