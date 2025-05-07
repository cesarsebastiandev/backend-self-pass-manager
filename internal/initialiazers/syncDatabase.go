package initialiazers

import (
	"github.com/cesarsebastiandev/backend-self-pass-manager/internal/models"
)

func SyncDatabase() {
	//Migrate the schema
	DB.AutoMigrate(&models.User{})
	DB.AutoMigrate(&models.Credential{})
}
