package models

import "gorm.io/gorm"

type Credential struct {
	gorm.Model
	Platform    string `gorm:"not null"`
	Description string `gorm:"not null"`
	Email       string `gorm:"unique"`
	Secret      string `json:"-"`
	MasterKey   string `json:"-"`
}
