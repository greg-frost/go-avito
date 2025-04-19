package model

import "time"

type PVZ struct {
	ID               string    `json:"id,omitempty"`
	RegistrationDate time.Time `json:"registrationDate,omitempty"`
	City             City      `json:"city"`
}

type PvzDTO struct {
	City City `json:"city"`
}

type PVZResult struct {
	PVZ        PVZ               `json:"pvz"`
	Receptions []ReceptionResult `json:"receptions"`
}

type City string

const (
	CityMoscow          City = "Москва"
	CitySaintPetersburg City = "Санкт-Петербург"
	CityKazan           City = "Казань"
)

func (c City) Valid() bool {
	switch c {
	case CityMoscow, CitySaintPetersburg, CityKazan:
		return true
	default:
		return false
	}
}
