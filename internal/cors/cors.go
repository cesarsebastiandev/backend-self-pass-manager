package cors

import (
	"os"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func CORSConfig() gin.HandlerFunc {

	allowedOrigins := strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",")

	if len(allowedOrigins) == 0 || allowedOrigins[0] == "" {
		//Allows all origins for local testing
		return cors.Default()
	}

	config := cors.Config{
		AllowOrigins:     allowedOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		// Sets the maximum time (12 hours) that the results of a preflight request can be cached by the browser.
		MaxAge:           12 * time.Hour,
	}

	return cors.New(config)
}
