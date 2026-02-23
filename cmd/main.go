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
	"strings"
)

func init() {
	initialiazers.LoadEnvVariables()
	initialiazers.ConnectToDb()
	initialiazers.SyncDatabase()
}

//@title Backend Self Pass Manager API
//@version 1
//@description RESTful API for managing passwords securely in Backend Self Pass Manager project.

// @contact.name Eng. Cesar Sebastian
// @contact.url https://github.com/cesarsebastiandev
// @contact.email cesarsebastian.dev@email.com

// @securityDefinitions.apikey bearerToken
// @in header
// @name Authorization

// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT

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

	// --- Static files ---
	r.Static("/browser", "./internal/static/browser") // JS, CSS, chunks, favicon
	r.Static("/assets", "./internal/static/assets")   // imágenes

	// --- SPA fallback ---
	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api") {
			c.JSON(404, gin.H{"error": "Not found"})
			return
		}
		// All other requests serve the Angular index.html file
		c.File("./internal/static/browser/index.html")
	})

	err := r.Run()
	if err != nil {
		log.Fatal(err)
	}

}
