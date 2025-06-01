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

	api := r.Group("/api/v1")
	{
		//Public routes
		api.POST("/register", controllers.Signup)
		api.POST("/login", controllers.Login)

		//Private routes
		api.POST("/logout", middlewares.RequireAuth, controllers.Logout)
		api.GET("/profile", middlewares.RequireAuth, controllers.Validate)
		api.POST("/credentials", middlewares.RequireAuth, controllers.AddCredentials)
		api.GET("/credentials", middlewares.RequireAuth, controllers.GetAllCredentials)
		api.GET("/credentials/:id", middlewares.RequireAuth, controllers.GetCredentialByID)
		api.PATCH("/credentials/:id", middlewares.RequireAuth, controllers.UpdateCredentialByID)
		api.DELETE("/credentials/:id", middlewares.RequireAuth, controllers.DeleteCredentialByID)
		api.POST("/credentials/decrypt/:id", middlewares.RequireAuth, controllers.GetPasswordDecryptByID)
		api.GET("/credentials/email/:id", middlewares.RequireAuth, controllers.GetEmailByID)

	}

}
