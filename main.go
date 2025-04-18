package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
)

type Token struct {
	Role Role
	jwt.StandardClaims
}

type User struct {
	ID    UUID  `json:"id,omitempty"`
	Email Email `json:"email"`
	Role  Role  `json:"role"`
}

type UUID string
type Email string

type UserDTO struct {
	Role Role `json:"role"`
}

type Role string

const (
	RoleEmployee  Role = "employee"
	RoleModerator Role = "moderator"
)

func (r Role) Valid() bool {
	switch r {
	case RoleEmployee, RoleModerator:
		return true
	default:
		return false
	}
}

type PVZ struct {
	ID               UUID      `json:"id,omitempty"`
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

type Reception struct {
	ID       UUID      `json:"id,omitempty"`
	DateTime time.Time `json:"dateTime"`
	PvzID    UUID      `json:"pvzId"`
	Status   Status    `json:"status"`
}

type ReceptionDTO struct {
	PvzID UUID `json:"pvzId"`
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

type Product struct {
	ID          UUID      `json:"id,omitempty"`
	DateTime    time.Time `json:"dateTime,omitempty"`
	Type        Type      `json:"type"`
	ReceptionID UUID      `json:"receptionId"`
}

type ProductDTO struct {
	Type  Type `json:"type"`
	PvzID UUID `json:"pvzId"`
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

type Error struct {
	Code    int    `json:"-"`
	Message string `json:"message"`
}

func (e Error) Error() string {
	return fmt.Sprintf("%d: %s", e.Code, e.Message)
}

func Respond(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

func RespondWithError(w http.ResponseWriter, err Error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.Code)
	json.NewEncoder(w).Encode(err)
}

type roleCtx string

var roleKey roleCtx = "role"

func putRoleIntoContext(ctx context.Context, role Role) context.Context {
	return context.WithValue(ctx, roleKey, role)
}

func getRoleFromContext(ctx context.Context) Role {
	return ctx.Value(roleKey).(Role)
}

func dummyLogin(w http.ResponseWriter, r *http.Request) {
	var user UserDTO
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "invalid request",
		})
		return
	}

	role := user.Role
	if !role.Valid() {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "invalid role",
		})
		return
	}

	tk := &Token{Role: role}
	token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)
	tokenString, _ := token.SignedString([]byte(os.Getenv("JWT_SECRET")))

	Respond(w, http.StatusOK, tokenString)
}

func createPVZ(w http.ResponseWriter, r *http.Request) {
	role := getRoleFromContext(r.Context())
	if role != RoleModerator {
		RespondWithError(w, Error{
			Code:    http.StatusForbidden,
			Message: "only for moderators",
		})
		return
	}

	var pvz PvzDTO
	if err := json.NewDecoder(r.Body).Decode(&pvz); err != nil {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "invalid request",
		})
		return
	}

	city := pvz.City
	if !city.Valid() {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "invalid city",
		})
		return
	}

	uuid := UUID(uuid.NewString())
	now := time.Now()
	_, err := db.Exec("INSERT INTO pvz(id, registration_date, city) VALUES($1, $2, $3)",
		uuid, now, city)
	if err != nil {
		log.Println("pvz insert error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "pvz was not created",
		})
		return
	}

	newPVZ := PVZ{
		ID:               uuid,
		RegistrationDate: now,
		City:             city,
	}

	Respond(w, http.StatusCreated, newPVZ)
}

func createReception(w http.ResponseWriter, r *http.Request) {
	role := getRoleFromContext(r.Context())
	if role != RoleEmployee {
		RespondWithError(w, Error{
			Code:    http.StatusForbidden,
			Message: "only for employees",
		})
		return
	}

	var reception ReceptionDTO
	if err := json.NewDecoder(r.Body).Decode(&reception); err != nil {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "invalid request",
		})
		return
	}

	pvzID := reception.PvzID
	_, err := db.Exec("SELECT id FROM pvz WHERE id=$1", pvzID)
	if err != nil {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "pvz not found",
		})
		return
	}

	result, err := db.Exec("SELECT id FROM reception WHERE pvz_id=$1 AND in_progress=true", pvzID)
	if err != nil {
		log.Println("reception check error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "reception was not created",
		})
		return
	}
	receptionsInProgress, _ := result.RowsAffected()

	if receptionsInProgress > 0 {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "other reception already in progress",
		})
		return
	}

	uuid := UUID(uuid.NewString())
	now := time.Now()
	_, err = db.Exec(`INSERT INTO reception(id, datetime, pvz_id, in_progress)
		VALUES($1, $2, $3, $4)`, uuid, now, pvzID, true)
	if err != nil {
		log.Println("reception insert error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "reception was not created",
		})
		return
	}

	newReception := Reception{
		ID:       uuid,
		DateTime: now,
		Status:   StatusInProgress,
		PvzID:    pvzID,
	}

	Respond(w, http.StatusCreated, newReception)
}

func closeLastReception(w http.ResponseWriter, r *http.Request) {
	role := getRoleFromContext(r.Context())
	if role != RoleEmployee {
		RespondWithError(w, Error{
			Code:    http.StatusForbidden,
			Message: "only for employees",
		})
		return
	}

	pvzID := UUID(mux.Vars(r)["pvzId"])
	_, err := db.Exec("SELECT id FROM pvz WHERE id=$1", pvzID)
	if err != nil {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "pvz not found",
		})
		return
	}

	var reception Reception
	var inProgress bool
	row := db.QueryRow(`SELECT id, datetime, in_progress FROM reception
		WHERE pvz_id=$1 ORDER BY datetime DESC LIMIT 1`, pvzID)
	if err := row.Scan(&reception.ID, &reception.DateTime, &inProgress); err != nil {
		if err == sql.ErrNoRows {
			RespondWithError(w, Error{
				Code:    http.StatusBadRequest,
				Message: "no reception in progress",
			})
			return
		}
		log.Println("reception close error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "reception was not closed",
		})
		return
	}
	if !inProgress {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "reception already closed",
		})
		return
	}

	_, err = db.Exec("UPDATE reception SET in_progress=false WHERE id=$1", reception.ID)
	if err != nil {
		log.Println("reception update error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "reception was not closed",
		})
		return
	}

	reception.PvzID = pvzID
	reception.Status = StatusClose

	Respond(w, http.StatusOK, reception)
}

func createProduct(w http.ResponseWriter, r *http.Request) {
	role := getRoleFromContext(r.Context())
	if role != RoleEmployee {
		RespondWithError(w, Error{
			Code:    http.StatusForbidden,
			Message: "only for employees",
		})
		return
	}

	var product ProductDTO
	if err := json.NewDecoder(r.Body).Decode(&product); err != nil {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "invalid request",
		})
		return
	}

	productType := product.Type
	if !productType.Valid() {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "invalid type",
		})
		return
	}

	pvzID := product.PvzID
	_, err := db.Exec("SELECT id FROM pvz WHERE id=$1", pvzID)
	if err != nil {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "pvz not found",
		})
		return
	}

	var reception Reception
	var inProgress bool
	row := db.QueryRow(`SELECT id, datetime, in_progress FROM reception
		WHERE pvz_id=$1 ORDER BY datetime DESC LIMIT 1`, pvzID)
	if err := row.Scan(&reception.ID, &reception.DateTime, &inProgress); err != nil {
		if err == sql.ErrNoRows {
			RespondWithError(w, Error{
				Code:    http.StatusBadRequest,
				Message: "no reception in progress",
			})
			return
		}
		log.Println("reception recieve error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "product was not created",
		})
		return
	}
	if !inProgress {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "no reception in progress",
		})
		return
	}

	uuid := UUID(uuid.NewString())
	now := time.Now()
	_, err = db.Exec(`INSERT INTO product(id, datetime, type, reception_id)
		VALUES($1, $2, $3, $4)`, uuid, now, productType, reception.ID)
	if err != nil {
		log.Println("product insert error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "product was not created",
		})
		return
	}

	newProduct := Product{
		ID:          uuid,
		DateTime:    now,
		Type:        productType,
		ReceptionID: reception.ID,
	}

	Respond(w, http.StatusCreated, newProduct)
}

func deleteLastProduct(w http.ResponseWriter, r *http.Request) {
	role := getRoleFromContext(r.Context())
	if role != RoleEmployee {
		RespondWithError(w, Error{
			Code:    http.StatusForbidden,
			Message: "only for employees",
		})
		return
	}

	pvzID := UUID(mux.Vars(r)["pvzId"])
	_, err := db.Exec("SELECT id FROM pvz WHERE id=$1", pvzID)
	if err != nil {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "pvz not found",
		})
		return
	}

	var reception Reception
	var inProgress bool
	row := db.QueryRow(`SELECT id, datetime, in_progress FROM reception
		WHERE pvz_id=$1 ORDER BY datetime DESC LIMIT 1`, pvzID)
	if err := row.Scan(&reception.ID, &reception.DateTime, &inProgress); err != nil {
		if err == sql.ErrNoRows {
			RespondWithError(w, Error{
				Code:    http.StatusBadRequest,
				Message: "no reception in progress",
			})
			return
		}
		log.Println("product delete error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "product was not deleted",
		})
		return
	}
	if !inProgress {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "no reception in progress",
		})
		return
	}

	var productID UUID
	row = db.QueryRow(`SELECT id FROM product WHERE reception_id=$1
		ORDER BY datetime DESC LIMIT 1`, reception.ID)
	if err := row.Scan(&productID); err != nil {
		if err == sql.ErrNoRows {
			RespondWithError(w, Error{
				Code:    http.StatusBadRequest,
				Message: "no products to delete",
			})
			return
		}
		log.Println("product select error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "product was not deleted",
		})
		return
	}

	_, err = db.Exec("DELETE FROM product WHERE id=$1", productID)
	if err != nil {
		log.Println("product delete error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "product was not deleted",
		})
		return
	}

	Respond(w, http.StatusOK, nil)
}

func getSummary(w http.ResponseWriter, r *http.Request) {
	role := getRoleFromContext(r.Context())
	if role != RoleEmployee && role != RoleModerator {
		RespondWithError(w, Error{
			Code:    http.StatusForbidden,
			Message: "only for employees and moderators",
		})
		return
	}

	pageInput := r.URL.Query().Get("page")
	page, _ := strconv.Atoi(pageInput)
	if page < 1 {
		page = 1
	}

	limitInput := r.URL.Query().Get("limit")
	limit, err := strconv.Atoi(limitInput)
	if err != nil {
		limit = 10
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 30 {
		limit = 30
	}

	startDateInput := r.URL.Query().Get("startDate")
	startDate, _ := time.Parse(time.RFC3339, startDateInput)

	endDateInput := r.URL.Query().Get("endDate")
	endDate, err := time.Parse(time.RFC3339, endDateInput)
	if err != nil {
		endDate = time.Now()
	}

	pvzs := make([]PVZ, 0, limit)
	pvzIDs := make([]UUID, 0, limit)
	pvzRows, err := db.Query(`
		SELECT p.id, p.registration_date, p.city FROM pvz p JOIN reception r ON p.id=r.pvz_id
		WHERE r.datetime BETWEEN $1 AND $2 GROUP BY p.id ORDER BY p.registration_date LIMIT $3 OFFSET $4`,
		startDate, endDate, limit, (page-1)*limit,
	)
	if err != nil && err != sql.ErrNoRows {
		log.Println("summary pvz select error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "internal server error",
		})
		return
	}
	defer pvzRows.Close()

	for pvzRows.Next() {
		var pvz PVZ
		if err := pvzRows.Scan(&pvz.ID, &pvz.RegistrationDate, &pvz.City); err != nil {
			log.Println("summary pvz rows scan error:", err)
			RespondWithError(w, Error{
				// Code:    http.StatusInternalServerError,
				Code:    http.StatusBadRequest,
				Message: "internal server error",
			})
			return
		}
		pvzs = append(pvzs, pvz)
		pvzIDs = append(pvzIDs, pvz.ID)
	}
	if err := pvzRows.Err(); err != nil {
		log.Println("summary pvz rows error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "internal server error",
		})
		return
	}

	receptions := make(map[UUID][]Reception, limit)
	var receptionsIDs []UUID
	receptionRows, err := db.Query(`
		SELECT id, datetime, pvz_id, in_progress FROM reception
		WHERE pvz_id=ANY($1) AND datetime BETWEEN $2 AND $3 ORDER BY datetime`,
		pq.Array(pvzIDs), startDate, endDate,
	)
	if err != nil && err != sql.ErrNoRows {
		log.Println("summary reception select error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "internal server error",
		})
		return
	}
	defer receptionRows.Close()

	for receptionRows.Next() {
		var reception Reception
		var inProgress bool
		if err := receptionRows.Scan(&reception.ID, &reception.DateTime,
			&reception.PvzID, &inProgress); err != nil {
			log.Println("summary reception rows scan error:", err)
			RespondWithError(w, Error{
				// Code:    http.StatusInternalServerError,
				Code:    http.StatusBadRequest,
				Message: "internal server error",
			})
			return
		}
		if inProgress {
			reception.Status = StatusInProgress
		} else {
			reception.Status = StatusClose
		}
		receptions[reception.PvzID] = append(receptions[reception.PvzID], reception)
		receptionsIDs = append(receptionsIDs, reception.ID)
	}
	if err := receptionRows.Err(); err != nil {
		log.Println("summary reception rows error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "internal server error",
		})
		return
	}

	products := make(map[UUID][]Product, len(receptionsIDs))
	productRows, err := db.Query(`
		SELECT id, datetime, type, reception_id FROM product
		WHERE reception_id=ANY($1) ORDER BY datetime`,
		pq.Array(receptionsIDs),
	)
	if err != nil && err != sql.ErrNoRows {
		log.Println("summary product select error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "internal server error",
		})
		return
	}
	defer productRows.Close()

	for productRows.Next() {
		var product Product
		if err := productRows.Scan(&product.ID, &product.DateTime,
			&product.Type, &product.ReceptionID); err != nil {
			log.Println("summary product rows scan error:", err)
			RespondWithError(w, Error{
				// Code:    http.StatusInternalServerError,
				Code:    http.StatusBadRequest,
				Message: "internal server error",
			})
			return
		}
		products[product.ReceptionID] = append(products[product.ReceptionID], product)
	}
	if err := productRows.Err(); err != nil {
		log.Println("summary product rows error:", err)
		RespondWithError(w, Error{
			// Code:    http.StatusInternalServerError,
			Code:    http.StatusBadRequest,
			Message: "internal server error",
		})
		return
	}

	summary := make([]PVZResult, 0, limit)
	for _, pvz := range pvzs {
		pvzResult := PVZResult{
			PVZ:        pvz,
			Receptions: make([]ReceptionResult, 0, len(receptions[pvz.ID])),
		}
		for _, reception := range receptions[pvz.ID] {
			receptionResult := ReceptionResult{
				Reception: reception,
				Products:  []Product{},
			}
			if receptionProducts, ok := products[reception.ID]; ok {
				receptionResult.Products = receptionProducts
			}
			pvzResult.Receptions = append(pvzResult.Receptions, receptionResult)
		}
		summary = append(summary, pvzResult)
	}

	Respond(w, http.StatusOK, summary)
}

var JwtAuthentication = func(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		skipAuth := []string{"/dummyLogin", "/register", "/login"}
		requestPath := r.URL.Path
		for _, path := range skipAuth {
			if path == requestPath {
				next.ServeHTTP(w, r)
				return
			}
		}

		tokenHeader := r.Header.Get("Authorization")
		if tokenHeader == "" {
			RespondWithError(w, Error{
				Code:    http.StatusForbidden,
				Message: "empty auth token",
			})
			return
		}

		tokenParts := strings.Split(tokenHeader, " ")
		if len(tokenParts) != 2 {
			RespondWithError(w, Error{
				Code:    http.StatusForbidden,
				Message: "malformed auth token",
			})
			return
		}

		tk := new(Token)
		tokenPart := tokenParts[1]
		token, err := jwt.ParseWithClaims(tokenPart, tk, func(token *jwt.Token) (interface{}, error) {
			return []byte(os.Getenv("JWT_SECRET")), nil
		})
		if err != nil {
			RespondWithError(w, Error{
				Code:    http.StatusForbidden,
				Message: "malformed jwt token",
			})
			return
		}

		if !token.Valid {
			RespondWithError(w, Error{
				Code:    http.StatusForbidden,
				Message: "invalid jwt token",
			})
			return
		}

		ctx := putRoleIntoContext(r.Context(), tk.Role)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func dbConnect(user, password, dbname string) (*sql.DB, error) {
	conn := fmt.Sprintf(
		"user=%s password=%s dbname=%s sslmode=disable",
		user, password, dbname,
	)
	db, err := sql.Open("postgres", conn)
	if err != nil {
		return nil, err
	}
	if err = db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

func dbSetup(db *sql.DB) error {
	queries := []string{
		// "DROP TYPE IF EXISTS pvz_city",
		// "CREATE TYPE pvz_city AS ENUM ('Москва', 'Санкт-Петербург', 'Казань')",
		// `CREATE TABLE IF NOT EXISTS pvz (
		// 	id uuid primary key,
		// 	registration_date timestamptz default now(),
		// 	city pvz_city
		// )`,
		`CREATE TABLE IF NOT EXISTS pvz (
			id uuid primary key,
			registration_date timestamptz default now(),
			city varchar(50) not null
		)`,
		`CREATE TABLE IF NOT EXISTS reception (
			id uuid primary key,
			datetime timestamptz default now(),
			pvz_id uuid,
			in_progress bool default true
		)`,
		`CREATE TABLE IF NOT EXISTS product (
			id uuid primary key,
			datetime timestamptz default now(),
			type varchar(50) not null,
			reception_id uuid
		)`,
	}

	for _, query := range queries {
		_, err := db.Exec(query)
		if err != nil {
			return err
		}
	}

	return nil
}

var db *sql.DB

func main() {
	fmt.Println(" \n[ AVITO INTERNSHIP ]\n ")

	router := mux.NewRouter()

	router.HandleFunc("/dummyLogin", dummyLogin).Methods("POST")
	router.HandleFunc("/pvz", createPVZ).Methods("POST")
	router.HandleFunc("/receptions", createReception).Methods("POST")
	router.HandleFunc("/pvz/{pvzId}/close_last_reception", closeLastReception).Methods("POST")
	router.HandleFunc("/products", createProduct).Methods("POST")
	router.HandleFunc("/pvz/{pvzId}/delete_last_product", deleteLastProduct).Methods("POST")
	router.HandleFunc("/", getSummary).Methods("GET")

	router.Use(JwtAuthentication)

	var err error
	db, err = dbConnect("postgres", "admin", "avito")
	if err != nil {
		log.Fatalf("database connection error: %v", err)
	}
	defer db.Close()

	if err = dbSetup(db); err != nil {
		log.Fatalf("database setup error: %v", err)
	}

	fmt.Println("Listening for connections...")
	fmt.Println("(on http://localhost:8080)")
	log.Fatal(http.ListenAndServe("localhost:8080", router))
}
