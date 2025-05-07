package main

import (
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/cors"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/initialiazers"
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/routes"

	"github.com/gin-gonic/gin"
)

func init() {
	initialiazers.LoadEnvVariables()
	initialiazers.ConnectToDb()
	initialiazers.SyncDatabase()
}

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

	r.Run() // listen and serve on 0.0.0.0:3000
}
