package postgres

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/greg-frost/go-avito/internal/model"
)

func setup(db *sql.DB) error {
	if err := createEnums(db); err != nil {
		return err
	}
	if err := createTables(db); err != nil {
		return err
	}
	return nil
}

func createEnums(db *sql.DB) error {
	enums := map[string][]interface{}{
		"pvz_city": {
			model.CityMoscow,
			model.CitySaintPetersburg,
			model.CityKazan,
		},
		"reception_status": {
			model.StatusInProgress,
			model.StatusClose,
		},
		"product_type": {
			model.TypeElectronics,
			model.TypeClothes,
			model.TypeShoes,
		},
	}
	for name, values := range enums {
		var exists bool
		row := db.QueryRow(`
			SELECT EXISTS (
				SELECT true
				FROM pg_type
				WHERE typname=$1
			)`,
			name,
		)
		if err := row.Scan(&exists); err != nil {
			return err
		}
		if !exists {
			var strValues []string
			for _, value := range values {
				strValues = append(strValues, fmt.Sprint(value))
			}
			if _, err := db.Exec(
				fmt.Sprintf(
					"CREATE TYPE %s AS ENUM('%s')",
					name, strings.Join(strValues, "','"),
				),
			); err != nil {
				return err
			}
		}
	}

	return nil
}

func createTables(db *sql.DB) error {
	tables := []string{
		`CREATE TABLE IF NOT EXISTS pvz (
			id uuid PRIMARY KEY,
			registration_date timestamptz DEFAULT now(),
			city pvz_city
		)`,
		`CREATE TABLE IF NOT EXISTS reception (
			id uuid PRIMARY KEY,
			datetime timestamptz DEFAULT now(),
			pvz_id uuid,
			status reception_status,
			FOREIGN KEY (pvz_id) REFERENCES pvz(id)
				ON DELETE CASCADE
		)`,
		`CREATE INDEX IF NOT EXISTS reception_datetime_idx
			ON reception(datetime)`,
		`CREATE TABLE IF NOT EXISTS product (
			id uuid PRIMARY KEY,
			datetime timestamptz DEFAULT now(),
			type product_type,
			reception_id uuid,
			FOREIGN KEY (reception_id) REFERENCES reception(id)
				ON DELETE CASCADE
		)`,
	}

	for _, table := range tables {
		if _, err := db.Exec(table); err != nil {
			return err
		}
	}

	return nil
}
