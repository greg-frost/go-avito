package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

type UUID string
type Email string

type Token struct {
	Role Role
	jwt.StandardClaims
}

type User struct {
	ID    UUID  `json:"id,omitempty"`
	Email Email `json:"email"`
	Role  Role  `json:"role"`
}

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

type City string

// const (
// 	CityMoscow          City = "Москва"
// 	CitySaintPetersburg City = "Санкт-Петербург"
// 	CityKazan           City = "Казань"
// )

const (
	CityMoscow          City = "Moscow"
	CitySaintPetersburg City = "Saint Petersburg"
	CityKazan           City = "Kazan"
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

// const (
// 	TypeElectronics Type = "электроника"
// 	TypeClothes     Type = "одежда"
// 	TypeShoes       Type = "обувь"
// )

const (
	TypeElectronics Type = "electronics"
	TypeClothes     Type = "clothes"
	TypeShoes       Type = "shoes"
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
	role := r.Context().Value("role")
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

	newPVZ := PVZ{
		ID:               "1234567890",
		RegistrationDate: time.Now(),
		City:             city,
	}

	Respond(w, http.StatusCreated, newPVZ)
}

func createReception(w http.ResponseWriter, r *http.Request) {
	role := r.Context().Value("role")
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
	if pvzID == "" {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "empty pvzId",
		})
		return
	}

	newReception := Reception{
		ID:       "0987654321",
		PvzID:    pvzID,
		DateTime: time.Now(),
		Status:   StatusInProgress,
	}

	Respond(w, http.StatusCreated, newReception)
}

func closeLastReception(w http.ResponseWriter, r *http.Request) {
	role := r.Context().Value("role")
	if role != RoleEmployee {
		RespondWithError(w, Error{
			Code:    http.StatusForbidden,
			Message: "only for employees",
		})
		return
	}

	pvzID := UUID(mux.Vars(r)["pvzId"])
	if pvzID == "" {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "empty pvzId",
		})
		return
	}

	reception := Reception{
		ID:       "0987654321",
		PvzID:    pvzID,
		DateTime: time.Now(),
		Status:   StatusInProgress,
	}

	if reception.Status == StatusClose {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "reception already closed",
		})
		return
	}
	reception.Status = StatusClose

	Respond(w, http.StatusOK, reception)
}

func createProduct(w http.ResponseWriter, r *http.Request) {
	role := r.Context().Value("role")
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

	pvzID := product.PvzID
	if pvzID == "" {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "empty pvzId",
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

	newProduct := Product{
		ID:          "1029384756",
		DateTime:    time.Now(),
		Type:        productType,
		ReceptionID: "0987654321",
	}

	Respond(w, http.StatusCreated, newProduct)
}

func deleteLastProduct(w http.ResponseWriter, r *http.Request) {
	role := r.Context().Value("role")
	if role != RoleEmployee {
		RespondWithError(w, Error{
			Code:    http.StatusForbidden,
			Message: "only for employees",
		})
		return
	}

	pvzID := UUID(mux.Vars(r)["pvzId"])
	if pvzID == "" {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "empty pvzId",
		})
		return
	}

	reception := Reception{
		ID:       "0987654321",
		PvzID:    pvzID,
		DateTime: time.Now(),
		Status:   StatusInProgress,
	}

	if reception.Status == StatusClose {
		RespondWithError(w, Error{
			Code:    http.StatusBadRequest,
			Message: "reception is closed",
		})
		return
	}

	Respond(w, http.StatusOK, nil)
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

		ctx := context.WithValue(r.Context(), "role", tk.Role)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

func main() {
	fmt.Println(" \n[ AVITO INTERNSHIP ]\n ")

	router := mux.NewRouter()

	router.HandleFunc("/dummyLogin", dummyLogin).Methods("POST")
	router.HandleFunc("/pvz", createPVZ).Methods("POST")
	router.HandleFunc("/receptions", createReception).Methods("POST")
	router.HandleFunc("/pvz/{pvzId}/close_last_reception", closeLastReception).Methods("POST")
	router.HandleFunc("/products", createProduct).Methods("POST")
	router.HandleFunc("/pvz/{pvzId}/delete_last_product", deleteLastProduct).Methods("POST")

	router.Use(JwtAuthentication)

	fmt.Println("Listening for connections...")
	fmt.Println("(on http://localhost:8080)")
	log.Fatal(http.ListenAndServe("localhost:8080", router))
}
