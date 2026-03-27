package nixstore

import (
	"database/sql"
)

// Database models from the nix store
type DerivationOutput struct {
	Drv int64 `db:"drv"`
	Id string `db:"id"`
	Path string `db:"path"`
}

type Refs struct {
	Referrer int64 `db:"referrer"`
	Reference int64 `db:"reference"`
}

type ValidPaths struct {
	Id int64 `db:"id"`
	Path string `db:"path"`
	Hash string `db:"hash"`
	RegistrationTime int64 `db:"registrationTime"`
	Deriver sql.Null[string] `db:"deriver"`
	NarSize uint64 `db:"narSize"`
	Ultimate sql.Null[int64] `db:"ultimate"`
	Sigs sql.Null[string] `db:"sigs"`
	Ca sql.Null[string] `db:"ca"`
}