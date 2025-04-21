package storage

import (
	"time"

	"github.com/greg-frost/go-avito/internal/model"
)

type Storage interface {
	CreatePVZ(pvz model.PVZ) error
	FindPVZ(pvzID string) (model.PVZ, error)
	ListPVZ(page, limit int, startDate, endDate time.Time, filterByDate bool) ([]model.PVZ, error)
	DeletePVZ(pvzID string) error
	CreateReception(reception model.Reception) error
	FindLastReception(pvzID string) (model.Reception, error)
	ListReceptions(pvzIDs []string, startDate, endDate time.Time) (map[string][]model.Reception, error)
	CloseReception(receptionID string) error
	DeleteReception(receptionID string) error
	CreateProduct(product model.Product) error
	FindLastProduct(receptionID string) (model.Product, error)
	ListProducts(receptionsIDs []string) (map[string][]model.Product, error)
	DeleteProduct(productID string) error
}
