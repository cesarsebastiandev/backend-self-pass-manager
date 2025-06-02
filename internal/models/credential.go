package models

import (
	"time"
)

// type Credential struct {
// 	gorm.Model
// 	Platform    string `gorm:"not null"`
// 	Description string `gorm:"not null"`
// 	Email       string `gorm:"unique"`
// 	Secret      string `json:"-"`
// 	MasterKey   string `json:"-"`
// }

type Credential struct {
	ID        uint       `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" gorm:"index"`

	Platform    string `json:"platform" gorm:"not null"`
	Description string `json:"description" gorm:"not null"`
	Email       string `json:"email"`
	Secret      string `json:"-"`
	MasterKey   string `json:"-"`
}
