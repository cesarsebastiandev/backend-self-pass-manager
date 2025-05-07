package routes

import (
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/controllers"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/middlewares"
	"github.com/gin-gonic/gin"
)

func SetupAllRoutes(r *gin.Engine) {

	r.GET("/api/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	//Public routes
	r.POST("/api/register", controllers.Signup)
	r.POST("/api/login", controllers.Login)

	//Private routes
	r.POST("/api/logout", middlewares.RequireAuth, controllers.Logout)
	r.GET("/api/profile", middlewares.RequireAuth, controllers.Validate)
	r.POST("/api/credentials", middlewares.RequireAuth, controllers.AddCredentials)
	r.GET("/api/credentials", middlewares.RequireAuth, controllers.GetAllCredentials)
	r.GET("/api/credentials/:id", middlewares.RequireAuth, controllers.GetCredentialByID)
	r.PATCH("/api/credentials/:id", middlewares.RequireAuth, controllers.UpdateCredentialByID)
	r.DELETE("/api/credentials/:id", middlewares.RequireAuth, controllers.DeleteCredentialByID)
	r.POST("/api/credentials/decrypt/:id", middlewares.RequireAuth, controllers.GetPasswordDecryptByID)
	r.GET("/api/credentials/email/:id", middlewares.RequireAuth, controllers.GetEmailByID)
}
