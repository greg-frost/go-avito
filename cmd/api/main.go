package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/greg-frost/go-avito/internal/auth"
	"github.com/greg-frost/go-avito/internal/model"
	"github.com/greg-frost/go-avito/internal/storage"
	u "github.com/greg-frost/go-avito/internal/utils"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

func dummyLogin(w http.ResponseWriter, r *http.Request) {
	var user model.UserDTO
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "invalid request",
		})
		return
	}

	role := user.Role
	if !role.Valid() {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "invalid role",
		})
		return
	}

	token := model.Token{Role: role}
	tokenString, err := token.SignedString()
	if err != nil {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusInternalServerError,
			Message: "token was not created",
		})
		return
	}

	u.Respond(w, http.StatusOK, tokenString)
}

func createPVZ(w http.ResponseWriter, r *http.Request) {
	role := u.GetRoleFromContext(r.Context())
	if role != model.RoleModerator {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusForbidden,
			Message: "only for moderators",
		})
		return
	}

	var pvz model.PvzDTO
	if err := json.NewDecoder(r.Body).Decode(&pvz); err != nil {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "invalid request",
		})
		return
	}

	city := pvz.City
	if !city.Valid() {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "invalid city",
		})
		return
	}

	newPVZ := model.PVZ{
		ID:               uuid.NewString(),
		RegistrationDate: time.Now(),
		City:             city,
	}

	if err := s.CreatePVZ(newPVZ); err != nil {
		log.Println("pvz insert error:", err)
		u.RespondWithError(w, model.Error{
			Code:    http.StatusInternalServerError,
			Message: "pvz was not created",
		})
		return
	}

	u.Respond(w, http.StatusCreated, newPVZ)
}

func createReception(w http.ResponseWriter, r *http.Request) {
	role := u.GetRoleFromContext(r.Context())
	if role != model.RoleEmployee {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusForbidden,
			Message: "only for employees",
		})
		return
	}

	var reception model.ReceptionDTO
	if err := json.NewDecoder(r.Body).Decode(&reception); err != nil {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "invalid request",
		})
		return
	}

	pvzID := reception.PvzID

	if _, err := s.FindPVZ(pvzID); err != nil {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "pvz not found",
		})
		return
	}

	lastReception, _ := s.FindLastReception(pvzID)
	if lastReception.Status == model.StatusInProgress {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "other reception already in progress",
		})
		return
	}

	newReception := model.Reception{
		ID:       uuid.NewString(),
		DateTime: time.Now(),
		PvzID:    pvzID,
		Status:   model.StatusInProgress,
	}

	if err := s.CreateReception(newReception); err != nil {
		log.Println("reception insert error:", err)
		u.RespondWithError(w, model.Error{
			Code:    http.StatusInternalServerError,
			Message: "reception was not created",
		})
		return
	}

	u.Respond(w, http.StatusCreated, newReception)
}

func closeLastReception(w http.ResponseWriter, r *http.Request) {
	role := u.GetRoleFromContext(r.Context())
	if role != model.RoleEmployee {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusForbidden,
			Message: "only for employees",
		})
		return
	}

	pvzID := mux.Vars(r)["pvzId"]

	lastReception, _ := s.FindLastReception(pvzID)
	if lastReception.Status != model.StatusInProgress {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "no reception in progress",
		})
		return
	}

	if err := s.CloseReception(lastReception.ID); err != nil {
		log.Println("reception update error:", err)
		u.RespondWithError(w, model.Error{
			Code:    http.StatusInternalServerError,
			Message: "reception was not closed",
		})
		return
	}
	lastReception.Status = model.StatusClose

	u.Respond(w, http.StatusOK, lastReception)
}

func createProduct(w http.ResponseWriter, r *http.Request) {
	role := u.GetRoleFromContext(r.Context())
	if role != model.RoleEmployee {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusForbidden,
			Message: "only for employees",
		})
		return
	}

	var product model.ProductDTO
	if err := json.NewDecoder(r.Body).Decode(&product); err != nil {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "invalid request",
		})
		return
	}

	productType := product.Type
	if !productType.Valid() {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "invalid type",
		})
		return
	}

	pvzID := product.PvzID

	lastReception, _ := s.FindLastReception(pvzID)
	if lastReception.Status != model.StatusInProgress {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "no reception in progress",
		})
		return
	}

	newProduct := model.Product{
		ID:          uuid.NewString(),
		DateTime:    time.Now(),
		Type:        productType,
		ReceptionID: lastReception.ID,
	}

	if err := s.CreateProduct(newProduct); err != nil {
		log.Println("product insert error:", err)
		u.RespondWithError(w, model.Error{
			Code:    http.StatusInternalServerError,
			Message: "product was not created",
		})
		return
	}

	u.Respond(w, http.StatusCreated, newProduct)
}

func deleteLastProduct(w http.ResponseWriter, r *http.Request) {
	role := u.GetRoleFromContext(r.Context())
	if role != model.RoleEmployee {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusForbidden,
			Message: "only for employees",
		})
		return
	}

	pvzID := mux.Vars(r)["pvzId"]

	lastReception, _ := s.FindLastReception(pvzID)
	if lastReception.Status != model.StatusInProgress {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "no reception in progress",
		})
		return
	}

	lastProduct, err := s.FindLastProduct(lastReception.ID)
	if err != nil {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "no products to delete",
		})
		return
	}

	if err := s.DeleteProduct(lastProduct.ID); err != nil {
		log.Println("product delete error:", err)
		u.RespondWithError(w, model.Error{
			Code:    http.StatusInternalServerError,
			Message: "product was not deleted",
		})
		return
	}

	u.Respond(w, http.StatusOK, nil)
}

const (
	summaryPageDefault  = 1
	summaryPageMin      = 1
	summaryLimitDefault = 10
	summaryLimitMin     = 1
	summaryLimitMax     = 30
)

func getSummary(w http.ResponseWriter, r *http.Request) {
	role := u.GetRoleFromContext(r.Context())
	if role != model.RoleEmployee && role != model.RoleModerator {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusForbidden,
			Message: "only for employees and moderators",
		})
		return
	}

	pageInput := r.URL.Query().Get("page")
	page, err := strconv.Atoi(pageInput)
	if err != nil {
		page = summaryPageDefault
	}
	if page < summaryPageMin {
		page = summaryPageMin
	}

	limitInput := r.URL.Query().Get("limit")
	limit, err := strconv.Atoi(limitInput)
	if err != nil {
		limit = summaryLimitDefault
	}
	if limit < summaryLimitMin {
		limit = summaryLimitMin
	}
	if limit > summaryLimitMax {
		limit = summaryLimitMax
	}

	var filterByDate bool
	startDateInput := r.URL.Query().Get("startDate")
	startDate, err := time.Parse(time.RFC3339, startDateInput)
	if err == nil {
		filterByDate = true
	}
	endDateInput := r.URL.Query().Get("endDate")
	endDate, err := time.Parse(time.RFC3339, endDateInput)
	if err != nil {
		endDate = time.Now()
	} else {
		filterByDate = true
	}

	pvzs, err := s.ListPVZ(page, limit, startDate, endDate, filterByDate)
	if err != nil {
		log.Println("summary pvzs select error:", err)
		u.RespondWithError(w, model.Error{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
		})
		return
	}
	pvzIDs := make([]string, 0, len(pvzs))
	for _, pvz := range pvzs {
		pvzIDs = append(pvzIDs, pvz.ID)
	}

	receptions, err := s.ListReceptions(pvzIDs, startDate, endDate)
	if err != nil {
		log.Println("summary receptions select error:", err)
		u.RespondWithError(w, model.Error{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
		})
		return
	}
	var receptionsIDs []string
	for _, rcps := range receptions {
		for _, reception := range rcps {
			receptionsIDs = append(receptionsIDs, reception.ID)
		}
	}

	products, err := s.ListProducts(receptionsIDs)
	if err != nil {
		log.Println("summary products select error:", err)
		u.RespondWithError(w, model.Error{
			Code:    http.StatusInternalServerError,
			Message: "internal server error",
		})
		return
	}

	results := make([]model.PVZResult, 0, len(pvzs))
	for _, pvz := range pvzs {
		pvzResult := model.PVZResult{
			PVZ:        pvz,
			Receptions: make([]model.ReceptionResult, 0, len(receptions[pvz.ID])),
		}
		for _, reception := range receptions[pvz.ID] {
			receptionResult := model.ReceptionResult{
				Reception: reception,
				Products:  make([]model.Product, 0),
			}
			if receptionProducts, ok := products[reception.ID]; ok {
				receptionResult.Products = receptionProducts
			}
			pvzResult.Receptions = append(pvzResult.Receptions, receptionResult)
		}
		results = append(results, pvzResult)
	}

	u.Respond(w, http.StatusOK, results)
}

func dbConnect(user, password, dbname string) (*sql.DB, error) {
	dsn := fmt.Sprintf(
		"user=%s password=%s dbname=%s sslmode=disable",
		user, password, dbname,
	)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

func dbSetup(db *sql.DB) error {
	enums := map[string][]interface{}{
		"pvz_city":         {model.CityMoscow, model.CitySaintPetersburg, model.CityKazan},
		"reception_status": {model.StatusInProgress, model.StatusClose},
		"product_type":     {model.TypeElectronics, model.TypeClothes, model.TypeShoes},
	}
	for name, values := range enums {
		var exists bool
		row := db.QueryRow(`
			SELECT EXISTS (
				SELECT true
				FROM pg_type
				WHERE typname = $1
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

var s *storage.Storage
var db *sql.DB

func main() {
	fmt.Println(" \n[ AVITO INTERNSHIP ]\n ")

	addr := flag.String("addr", "localhost", "server address")
	port := flag.Int("port", 8080, "server port")
	flag.Parse()

	router := mux.NewRouter()

	router.HandleFunc("/dummyLogin", dummyLogin).Methods("POST")
	router.HandleFunc("/pvz", createPVZ).Methods("POST")
	router.HandleFunc("/receptions", createReception).Methods("POST")
	router.HandleFunc("/pvz/{pvzId}/close_last_reception", closeLastReception).Methods("POST")
	router.HandleFunc("/products", createProduct).Methods("POST")
	router.HandleFunc("/pvz/{pvzId}/delete_last_product", deleteLastProduct).Methods("POST")
	router.HandleFunc("/", getSummary).Methods("GET")

	router.Use(auth.JwtAuthentication)

	var err error
	db, err = dbConnect("postgres", "admin", "avito")
	if err != nil {
		log.Fatalf("database connect error: %v", err)
	}
	defer db.Close()

	if err = dbSetup(db); err != nil {
		log.Fatalf("database setup error: %v", err)
	}

	s = storage.NewStorage(db)

	connAddr := fmt.Sprintf("%s:%d", *addr, *port)
	fmt.Println("Listening for connections...")
	fmt.Println("(on http://" + connAddr + ")")
	log.Fatal(http.ListenAndServe(connAddr, router))
}
