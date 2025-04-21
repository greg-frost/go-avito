package postgres

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/greg-frost/go-avito/internal/model"
	s "github.com/greg-frost/go-avito/internal/storage"

	"github.com/lib/pq"
)

type storage struct {
	db *sql.DB
}

func NewStorage(params ConnectionParams) (s.Storage, error) {
	db, err := connect(params)
	if err != nil {
		return nil, fmt.Errorf("db connect error: %w", err)
	}

	if err = setup(db); err != nil {
		return nil, fmt.Errorf("db setup error: %w", err)
	}

	return &storage{db: db}, nil
}

func (s *storage) CreatePVZ(pvz model.PVZ) error {
	_, err := s.db.Exec(`
		INSERT INTO pvz(id, registration_date, city)
		VALUES($1, $2, $3)`,
		pvz.ID,
		pvz.RegistrationDate,
		pvz.City,
	)

	return err
}

func (s *storage) FindPVZ(pvzID string) (model.PVZ, error) {
	var pvz model.PVZ
	row := s.db.QueryRow(`
		SELECT id, registration_date, city
		FROM pvz
		WHERE id=$1`,
		pvzID,
	)
	err := row.Scan(&pvz.ID, &pvz.RegistrationDate, &pvz.City)
	return pvz, err
}

func (s *storage) ListPVZ(page, limit int, startDate, endDate time.Time, filterByDate bool) (
	[]model.PVZ, error) {
	results := make([]model.PVZ, 0, limit)

	var rows *sql.Rows
	var err error
	if !filterByDate {
		rows, err = s.db.Query(`
			SELECT id, registration_date, city
			FROM pvz
			ORDER BY registration_date
			LIMIT $1 OFFSET $2`,
			limit, (page-1)*limit,
		)
	} else {
		rows, err = s.db.Query(`
			SELECT p.id, p.registration_date, p.city
			FROM pvz p
			JOIN reception r ON p.id=r.pvz_id
			WHERE r.datetime BETWEEN $1 AND $2
			GROUP BY p.id
			ORDER BY p.registration_date
			LIMIT $3 OFFSET $4`,
			startDate, endDate, limit, (page-1)*limit,
		)
	}
	if err != nil && err != sql.ErrNoRows {
		return results, err
	}
	defer rows.Close()

	for rows.Next() {
		var pvz model.PVZ
		if err := rows.Scan(&pvz.ID, &pvz.RegistrationDate, &pvz.City); err != nil {
			return results, err
		}
		results = append(results, pvz)
	}
	if err := rows.Err(); err != nil {
		return results, err
	}

	return results, nil
}

func (s *storage) DeletePVZ(pvzID string) error {
	_, err := s.db.Exec(`
		DELETE FROM pvz
		WHERE id=$1`,
		pvzID,
	)

	return err
}

func (s *storage) CreateReception(reception model.Reception) error {
	_, err := s.db.Exec(`
		INSERT INTO reception(id, datetime, pvz_id, status)
		VALUES($1, $2, $3, $4)`,
		reception.ID,
		reception.DateTime,
		reception.PvzID,
		model.StatusInProgress,
	)

	return err
}

func (s *storage) FindLastReception(pvzID string) (model.Reception, error) {
	var reception model.Reception
	row := s.db.QueryRow(`
		SELECT id, datetime, pvz_id, status
		FROM reception
		WHERE pvz_id=$1
		ORDER BY datetime DESC
		LIMIT 1`,
		pvzID,
	)
	err := row.Scan(
		&reception.ID, &reception.DateTime,
		&reception.PvzID, &reception.Status,
	)
	return reception, err
}

func (s *storage) ListReceptions(pvzIDs []string, startDate, endDate time.Time) (
	map[string][]model.Reception, error) {
	results := make(map[string][]model.Reception, len(pvzIDs))

	rows, err := s.db.Query(`
		SELECT id, datetime, pvz_id, status
		FROM reception
		WHERE pvz_id=ANY($1) 
			AND datetime BETWEEN $2 AND $3
		ORDER BY datetime`,
		pq.Array(pvzIDs),
		startDate,
		endDate,
	)
	if err != nil && err != sql.ErrNoRows {
		return results, err
	}
	defer rows.Close()

	for rows.Next() {
		var reception model.Reception
		if err := rows.Scan(&reception.ID, &reception.DateTime,
			&reception.PvzID, &reception.Status); err != nil {
			return results, err
		}
		results[reception.PvzID] = append(results[reception.PvzID], reception)
	}
	if err := rows.Err(); err != nil {
		return results, err
	}

	return results, nil
}

func (s *storage) CloseReception(receptionID string) error {
	_, err := s.db.Exec(`
		UPDATE reception
		SET status=$1
		WHERE id=$2`,
		model.StatusClose,
		receptionID,
	)

	return err
}

func (s *storage) DeleteReception(receptionID string) error {
	_, err := s.db.Exec(`
		DELETE FROM reception
		WHERE id=$1`,
		receptionID,
	)

	return err
}

func (s *storage) CreateProduct(product model.Product) error {
	_, err := s.db.Exec(`
		INSERT INTO product(id, datetime, type, reception_id)
		VALUES($1, $2, $3, $4)`,
		product.ID,
		product.DateTime,
		product.Type,
		product.ReceptionID,
	)

	return err
}

func (s *storage) FindLastProduct(receptionID string) (model.Product, error) {
	var product model.Product
	row := s.db.QueryRow(`
		SELECT id, datetime, type, reception_id
		FROM product
		WHERE reception_id=$1
		ORDER BY datetime DESC
		LIMIT 1`,
		receptionID,
	)
	err := row.Scan(
		&product.ID, &product.DateTime,
		&product.Type, &product.ReceptionID,
	)
	return product, err
}

func (s *storage) ListProducts(receptionsIDs []string) (
	map[string][]model.Product, error) {
	results := make(map[string][]model.Product, len(receptionsIDs))

	rows, err := s.db.Query(`
		SELECT id, datetime, type, reception_id
		FROM product
		WHERE reception_id=ANY($1)
		ORDER BY datetime`,
		pq.Array(receptionsIDs),
	)
	if err != nil && err != sql.ErrNoRows {
		return results, err
	}
	defer rows.Close()

	for rows.Next() {
		var product model.Product
		if err := rows.Scan(&product.ID, &product.DateTime,
			&product.Type, &product.ReceptionID); err != nil {
			return results, err
		}
		results[product.ReceptionID] = append(results[product.ReceptionID], product)
	}
	if err := rows.Err(); err != nil {
		return results, err
	}

	return results, nil
}

func (s *storage) DeleteProduct(productID string) error {
	_, err := s.db.Exec(`
		DELETE FROM product
		WHERE id=$1`,
		productID,
	)

	return err
}
