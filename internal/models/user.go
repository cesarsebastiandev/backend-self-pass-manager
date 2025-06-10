package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
	DeletedAt *time.Time         `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`

	Name     string `bson:"name" json:"name"`
	Lastname string `bson:"lastname" json:"lastname"`
	Email    string `bson:"email" json:"email"`
	Password string `bson:"password" json:"-"`
}
