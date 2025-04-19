package model

import "time"

type Product struct {
	ID          string    `json:"id,omitempty"`
	DateTime    time.Time `json:"dateTime,omitempty"`
	Type        Type      `json:"type"`
	ReceptionID string    `json:"receptionId"`
}

type ProductDTO struct {
	Type  Type   `json:"type"`
	PvzID string `json:"pvzId"`
}

type Type string

const (
	TypeElectronics Type = "электроника"
	TypeClothes     Type = "одежда"
	TypeShoes       Type = "обувь"
)

func (t Type) Valid() bool {
	switch t {
	case TypeElectronics, TypeClothes, TypeShoes:
		return true
	default:
		return false
	}
}
