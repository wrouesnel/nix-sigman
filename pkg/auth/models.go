package auth

import (
	"time"

	"gorm.io/gorm"
)

// ClientCACertificates implements the list of client CAs recognized by the server
// auth system.
type ClientCACertificates struct {
	Serial               uint64 `gorm:"primarykey"`
	SubjectKeyIdentifier []byte `gorm:"primarykey"`
	ThumbprintSHA256     []byte `gorm:"index:"`

	NotBefore time.Time `gorm:"index:"`
	NotAfter  time.Time `gorm:"index:"`
}

func DatabaseInitialize(db *gorm.DB) error {
	return db.AutoMigrate(&ClientCACertificates{})
}
