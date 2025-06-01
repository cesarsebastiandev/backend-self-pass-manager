package main

import (
	"log"

	_ "github.com/cesarsebastiandev/backend-self-pass-manager/docs"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/cors"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/initialiazers"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/routes"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"github.com/gin-gonic/gin"
)

func init() {
	initialiazers.LoadEnvVariables()
	initialiazers.ConnectToDb()
	initialiazers.SyncDatabase()
}

//@title Documenting API
//@version 1
//@description This is a restful API

// @contact.name Ing. Cesar Sebastian
// @contact.url https://github.com/cesarsebastiandev
// @contact.email cesarsebastian.dev@email.com

// @securityDefinitions.apikey bearerToken
// @in header
// @name Authorization

// @host localhost:3000
// @BasePath /api/v1

func main() {
	r := gin.Default()
	//Only for local enviroment
	r.SetTrustedProxies(nil)

	//Proxy example
	// r.SetTrustedProxies([]string{"192.168.1.2"})

	//It loads all routes
	routes.SetupAllRoutes(r)

	//It loads cors config
	r.Use(cors.CORSConfig())

	// Serve Swagger UI at /swagger for interactive API documentation
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	err := r.Run()
	if err != nil {
		log.Fatal(err)
	}

	r.Run() // listen and serve on 0.0.0.0:3000
}
