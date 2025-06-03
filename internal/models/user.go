package models

import "time"

// type User struct {
// 	gorm.Model
// 	Name     string `gorm:"not null"`
// 	Lastname string `gorm:"not null"`
// 	Email    string `gorm:"unique"`
// 	Password string `json:"-"`
// }

type User struct {
	ID        uint       `json:"id" gorm:"primaryKey"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty" gorm:"index"`
	Name      string     `json:"name" gorm:"not null"`
	Lastname  string     `json:"lastname" gorm:"not null"`
	Email     string     `json:"email" gorm:"unique"`
	Password  string     `json:"-"`
}
