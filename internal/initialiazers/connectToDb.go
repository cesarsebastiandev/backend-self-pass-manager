package initialiazers

import (
	"log"
	"os"

	"go.mongodb.org/mongo-driver/mongo"
)

var (
	UserCollection       *mongo.Collection
	CredentialCollection *mongo.Collection
)

func ConnectToDb() {
	mongoURI := os.Getenv("MONGO_URI")
	if mongoURI == "" {
		log.Fatal("MONGO_URI is not set in environment variables")
	}

	dbName := os.Getenv("MONGO_DB_NAME")
	if dbName == "" {
		log.Fatal("MONGO_DB_NAME is not set in environment variables")
	}

	client, err := ConnectClient(mongoURI)
	if err != nil {
		log.Fatal(err.Error())
	}

	database := client.Database(dbName)

	// Retrieve collections from the database; will be assigned to global variables later.
	UserCollection = database.Collection("users")
	CredentialCollection = database.Collection("credentials")

}
