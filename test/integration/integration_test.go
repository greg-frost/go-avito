//go:build integration

package integration

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/greg-frost/go-avito/internal/auth"
	"github.com/greg-frost/go-avito/internal/db/postgres"
	"github.com/greg-frost/go-avito/internal/handler"
	"github.com/greg-frost/go-avito/internal/model"
	"github.com/greg-frost/go-avito/internal/storage"

	"github.com/gorilla/mux"
)

var (
	r *mux.Router
	h handler.Handler
	s storage.Storage
)

func init() {
	r = mux.NewRouter()

	pgParams := postgres.ConnectionParams{
		DbName:   os.Getenv("DB_NAME"),
		User:     os.Getenv("DB_USER"),
		Password: os.Getenv("DB_PASS"),
		Host:     os.Getenv("DB_HOST"),
		Port:     os.Getenv("DB_PORT"),
	}
	var err error
	s, err = postgres.NewStorage(pgParams)
	if err != nil {
		log.Fatal(err)
	}

	h = handler.NewHandler(s)
	h.Register(r)

	r.Use(auth.JwtAuthentication)
}

func TestIntegration(t *testing.T) {
	t.Log("Started")

	moderatorToken, err := getToken("moderator")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Moderator token recieved:", "..."+
		moderatorToken[len(moderatorToken)-16:])

	pvzID, err := createPVZ(moderatorToken, randomCity())
	if err != nil {
		t.Fatal(err)
	}
	t.Log("PVZ created:", pvzID)

	defer func() {
		err := s.DeletePVZ(pvzID)
		if err != nil {
			t.Fatalf("PVZ with data was not deleted (ID: %s)", pvzID)
		}

		t.Log("Products deleted")
		t.Log("Reception deleted")
		t.Log("PVZ deleted")

		t.Log("Ended")
	}()

	employeeToken, err := getToken("employee")
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Employee token recieved:", "..."+
		employeeToken[len(employeeToken)-16:])

	receptionID, err := createReception(employeeToken, pvzID)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Reception created:", receptionID)

	productsCount := 50
	for i := 0; i < productsCount; i++ {
		_, err := createProduct(employeeToken, randomType(), pvzID)
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Log("Products created count:", productsCount)

	productID, err := createProduct(employeeToken, randomType(), pvzID)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("One more product created:", productID)

	err = deleteLastProduct(employeeToken, pvzID)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Last product deleted")

	err = closeLastReception(employeeToken, pvzID)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("Reception closed")
}

func getToken(role string) (string, error) {
	body := `{"role": "` + role + `"}`
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(
		"POST", "/dummyLogin",
		strings.NewReader(body))

	r.ServeHTTP(rec, req)
	if rec.Code != 200 {
		return "", fmt.Errorf("no token recieved for role %s: %w", role, getError(rec))
	}

	var token string
	json.NewDecoder(rec.Body).Decode(&token)
	return token, nil
}

func createPVZ(token, city string) (string, error) {
	body := `{"city": "` + city + `"}`
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(
		"POST", "/pvz",
		strings.NewReader(body))

	req.Header.Add("Authorization", "Bearer "+token)

	r.ServeHTTP(rec, req)
	if rec.Code != 201 {
		return "", fmt.Errorf("no pvz created for city %s: %w", city, getError(rec))
	}

	var pvz model.PVZ
	json.NewDecoder(rec.Body).Decode(&pvz)
	return pvz.ID, nil
}

func createReception(token, pvzID string) (string, error) {
	body := `{"pvzId": "` + pvzID + `"}`
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(
		"POST", "/receptions",
		strings.NewReader(body))

	req.Header.Add("Authorization", "Bearer "+token)

	r.ServeHTTP(rec, req)
	if rec.Code != 201 {
		return "", fmt.Errorf("no reception created for pvzId %s: %w", pvzID, getError(rec))
	}

	var reception model.Reception
	json.NewDecoder(rec.Body).Decode(&reception)
	return reception.ID, nil
}

func createProduct(token, productType, pvzID string) (string, error) {
	body := `{"type": "` + productType + `", "pvzId": "` + pvzID + `"}`
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(
		"POST", "/products",
		strings.NewReader(body))

	req.Header.Add("Authorization", "Bearer "+token)

	r.ServeHTTP(rec, req)
	if rec.Code != 201 {
		return "", fmt.Errorf("no product created for pvzId %s: %w", pvzID, getError(rec))
	}

	var product model.Product
	json.NewDecoder(rec.Body).Decode(&product)
	return product.ID, nil
}

func deleteLastProduct(token, pvzID string) error {
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(
		"POST", "/pvz/"+pvzID+"/delete_last_product", nil)

	req.Header.Add("Authorization", "Bearer "+token)

	r.ServeHTTP(rec, req)
	if rec.Code != 200 {
		return fmt.Errorf("no product deleted for pvzId %s: %w", pvzID, getError(rec))
	}

	return nil
}

func closeLastReception(token, pvzID string) error {
	rec := httptest.NewRecorder()
	req, _ := http.NewRequest(
		"POST", "/pvz/"+pvzID+"/close_last_reception", nil)

	req.Header.Add("Authorization", "Bearer "+token)

	r.ServeHTTP(rec, req)
	if rec.Code != 200 {
		return fmt.Errorf("no reception closed for pvzId %s: %w", pvzID, getError(rec))
	}

	return nil
}

func getError(rec *httptest.ResponseRecorder) model.Error {
	var err model.Error
	json.NewDecoder(rec.Body).Decode(&err)
	err.Code = rec.Code
	return err
}

func randomCity() string {
	cities := []model.City{
		model.CityMoscow,
		model.CitySaintPetersburg,
		model.CityKazan,
	}
	i := rand.Intn(len(cities))
	return string(cities[i])
}

func randomType() string {
	types := []model.Type{
		model.TypeElectronics,
		model.TypeClothes,
		model.TypeShoes,
	}
	i := rand.Intn(len(types))
	return string(types[i])
}
