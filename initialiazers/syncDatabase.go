package initialiazers

import (
	"github.com/cesarsebastiandev/backend-self-pass-manager/models"
)

func SyncDatabase() {
	//Migrate the schema
	DB.AutoMigrate(&models.User{})
}
