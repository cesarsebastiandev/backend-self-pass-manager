package models

import "gorm.io/gorm"

type Credential struct {
	gorm.Model
	Platform         string `gorm:"not null"`
	Description      string `gorm:"not null"`
	Email            string `gorm:"unique"`
	Password         string `json:"-"`
	PasswordToDecode string `json:"-"`
}
