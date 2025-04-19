package model

import "time"

type Reception struct {
	ID       string    `json:"id,omitempty"`
	DateTime time.Time `json:"dateTime"`
	PvzID    string    `json:"pvzId"`
	Status   Status    `json:"status"`
}

type ReceptionDTO struct {
	PvzID string `json:"pvzId"`
}

type ReceptionResult struct {
	Reception Reception `json:"reception"`
	Products  []Product `json:"products"`
}

type Status string

const (
	StatusInProgress Status = "in_progress"
	StatusClose      Status = "close"
)

func (s Status) Valid() bool {
	switch s {
	case StatusInProgress, StatusClose:
		return true
	default:
		return false
	}
}
