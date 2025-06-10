package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Credential struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
	DeletedAt *time.Time         `bson:"deleted_at,omitempty" json:"deleted_at,omitempty"`

	Platform    string `bson:"platform" json:"platform"`
	Description string `bson:"description" json:"description"`
	Email       string `bson:"email" json:"email"`
	Secret      string `bson:"secret" json:"-"`
	MasterKey   string `bson:"master_key" json:"-"`
}
