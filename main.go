package main

import (
	"github.com/cesarsebastiandev/backend-self-pass-manager/controllers"
	"github.com/cesarsebastiandev/backend-self-pass-manager/initialiazers"
	"github.com/cesarsebastiandev/backend-self-pass-manager/middleware"

	"github.com/gin-gonic/gin"
)

func init() {
	initialiazers.LoadEnvVariables()
	initialiazers.ConnectToDb()
	initialiazers.SyncDatabase()
}

func main() {
	r := gin.Default()
	r.GET("/api/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	//Public routes
	r.POST("/api/register", controllers.Signup)
	r.POST("/api/login", controllers.Login)
	
	//Private routes
	r.POST("/api/logout", middleware.RequireAuth, controllers.Logout)
	r.GET("/api/profile", middleware.RequireAuth, controllers.Validate)
	r.POST("/api/credentials", middleware.RequireAuth, controllers.AddCredentials)
	r.GET("/api/credentials", middleware.RequireAuth, controllers.GetAllCredentials)
	r.GET("/api/credentials/:id", middleware.RequireAuth, controllers.GetCredentialByID)
	r.PATCH("/api/credentials/:id", middleware.RequireAuth, controllers.UpdateCredentialByID)
	r.DELETE("/api/credentials/:id", middleware.RequireAuth, controllers.DeleteCredentialByID)
	r.POST("/api/credentials/decrypt/:id", middleware.RequireAuth, controllers.GetPasswordDecryptByID)



	r.Run() // listen and serve on 0.0.0.0:3000
}
