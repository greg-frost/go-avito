package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/greg-frost/go-avito/internal/auth"
	"github.com/greg-frost/go-avito/internal/db/mock"
	"github.com/greg-frost/go-avito/internal/model"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

var (
	r *mux.Router
	h Handler

	employeeToken  string
	moderatorToken string
	guestToken     string
)

func init() {
	r = mux.NewRouter()

	mockStorage := mock.NewStorage()
	h = NewHandler(mockStorage)
	h.Register(r)

	r.Use(auth.JwtAuthentication)

	employee := model.Token{Role: model.RoleEmployee}
	employeeToken, _ = employee.SignedString()

	moderator := model.Token{Role: model.RoleModerator}
	moderatorToken, _ = moderator.SignedString()

	guest := model.Token{Role: "guest"}
	guestToken, _ = guest.SignedString()
}

func TestDummyLogin(t *testing.T) {
	tests := []struct {
		test string
		body string
		code int
	}{
		{"Employee", `{"role": "employee"}`, 200},
		{"Moderator", `{"role": "moderator"}`, 200},
		{"Guest", `{"role": "guest"}`, 400},
		{"WrongKey", `{"rule": "employee"}`, 400},
		{"WrongValue", `{"role": 123}`, 400},
		{"Invalid", "role=employee", 400},
		{"Empty", "", 400},
	}

	for _, tt := range tests {
		t.Run(tt.test, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req, _ := http.NewRequest(
				"POST", "/dummyLogin",
				strings.NewReader(tt.body))

			r.ServeHTTP(rec, req)

			if rec.Code != tt.code {
				t.Errorf("%s: want code %d, got code %d", tt.body, tt.code, rec.Code)
			}
		})
	}
}

func TestCreatePVZ(t *testing.T) {
	tests := []struct {
		test string
		auth string
		body string
		code int
	}{
		{"Guest", guestToken, "", 403},
		{"Employee", employeeToken, "", 403},
		{"Moscow", moderatorToken, `{"city": "Москва"}`, 201},
		{"SaintPetersburg", moderatorToken, `{"city": "Санкт-Петербург"}`, 201},
		{"Kazan", moderatorToken, `{"city": "Казань"}`, 201},
		{"NizhnyNovgorod", moderatorToken, `{"city": "Нижний Новгород"}`, 400},
		{"WrongKey", moderatorToken, `{"gorod": "Москва"}`, 400},
		{"WrongValue", moderatorToken, `{"city": 123}`, 400},
		{"Invalid", moderatorToken, "city=moscow", 400},
		{"Empty", moderatorToken, "", 400},
	}

	for _, tt := range tests {
		t.Run(tt.test, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req, _ := http.NewRequest(
				"POST", "/pvz",
				strings.NewReader(tt.body))

			req.Header.Add("Authorization", "Bearer "+tt.auth)

			r.ServeHTTP(rec, req)

			if rec.Code != tt.code {
				t.Errorf("%s: want code %d, got code %d", tt.body, tt.code, rec.Code)
			}
		})
	}
}

func TestCreateReception(t *testing.T) {
	tests := []struct {
		test string
		auth string
		body string
		code int
	}{
		{"Guest", guestToken, "", 403},
		{"Moderator", moderatorToken, "", 403},
		{"Valid", employeeToken, `{"pvzId": "` + mock.PVZ.ID + `"}`, 201},
		{"Closed", employeeToken, `{"pvzId": "` + mock.PvzClosed.ID + `"}`, 201},
		{"InProgress", employeeToken, `{"pvzId": "` + mock.PvzInProgress.ID + `"}`, 400},
		{"NotFound", employeeToken, `{"pvzId": "` + uuid.NewString() + `"}`, 400},
		{"WrongKey", employeeToken, `{"pvz_id": "` + mock.PVZ.ID + `"}`, 400},
		{"WrongValue", employeeToken, `{"pvzID": 123}`, 400},
		{"Invalid", employeeToken, "pvz=" + mock.PVZ.ID, 400},
		{"Empty", employeeToken, "", 400},
	}

	for _, tt := range tests {
		t.Run(tt.test, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req, _ := http.NewRequest(
				"POST", "/receptions",
				strings.NewReader(tt.body))

			req.Header.Add("Authorization", "Bearer "+tt.auth)

			r.ServeHTTP(rec, req)

			if rec.Code != tt.code {
				t.Errorf("%s: want code %d, got code %d", tt.body, tt.code, rec.Code)
			}
		})
	}
}

func TestCloseLastReception(t *testing.T) {
	tests := []struct {
		test  string
		auth  string
		pvzID string
		code  int
	}{
		{"Guest", guestToken, uuid.NewString(), 403},
		{"Moderator", moderatorToken, uuid.NewString(), 403},
		{"InProgress", employeeToken, mock.PvzInProgress.ID, 200},
		{"NoReceptions", employeeToken, mock.PVZ.ID, 400},
		{"Closed", employeeToken, mock.PvzClosed.ID, 400},
		{"NotFound", employeeToken, uuid.NewString(), 400},
		{"Wrong", employeeToken, "123", 400},
		{"Empty", employeeToken, "", 301},
	}

	for _, tt := range tests {
		t.Run(tt.test, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req, _ := http.NewRequest(
				"POST", "/pvz/"+tt.pvzID+"/close_last_reception", nil)

			req.Header.Add("Authorization", "Bearer "+tt.auth)

			r.ServeHTTP(rec, req)

			if rec.Code != tt.code {
				t.Errorf("%s: want code %d, got code %d", tt.pvzID, tt.code, rec.Code)
			}
		})
	}
}

func TestCreateProduct(t *testing.T) {
	noRcpsPvzID := mock.PVZ.ID
	closedPvzID := mock.PvzClosed.ID
	inProgPvzID := mock.PvzInProgress.ID

	tests := []struct {
		test string
		auth string
		body string
		code int
	}{
		{"Guest", guestToken, "", 403},
		{"Moderator", moderatorToken, "", 403},
		{"Electronics", employeeToken, `{"type": "электроника", "pvzId": "` + inProgPvzID + `"}`, 201},
		{"Clothes", employeeToken, `{"type": "одежда", "pvzId": "` + inProgPvzID + `"}`, 201},
		{"Shoes", employeeToken, `{"type": "обувь", "pvzId": "` + inProgPvzID + `"}`, 201},
		{"Closed", employeeToken, `{"type": "обувь", "pvzId": "` + closedPvzID + `"}`, 400},
		{"NoReceptions", employeeToken, `{"type": "одежда", "pvzId": "` + noRcpsPvzID + `"}`, 400},
		{"Other", employeeToken, `{"type": "другое"}`, 400},
		{"WrongKey", employeeToken, `{"tip": "электроника", "pvz": "` + inProgPvzID + `"}`, 400},
		{"WrongValue", employeeToken, `{"type": 123, "pvzId": 456}`, 400},
		{"Invalid", employeeToken, "type=обувь&pvzId=" + mock.PvzInProgress.ID, 400},
		{"Empty", employeeToken, "", 400},
	}

	for _, tt := range tests {
		t.Run(tt.test, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req, _ := http.NewRequest(
				"POST", "/products",
				strings.NewReader(tt.body))

			req.Header.Add("Authorization", "Bearer "+tt.auth)

			r.ServeHTTP(rec, req)

			if rec.Code != tt.code {
				t.Errorf("%s: want code %d, got code %d", tt.body, tt.code, rec.Code)
			}
		})
	}
}

func TestDeleteLastProduct(t *testing.T) {
	tests := []struct {
		test  string
		auth  string
		pvzID string
		code  int
	}{
		{"Guest", guestToken, uuid.NewString(), 403},
		{"Moderator", moderatorToken, uuid.NewString(), 403},
		{"WithProducts", employeeToken, mock.PvzWithProducts.ID, 200},
		{"WithoutProducts", employeeToken, mock.PvzInProgress.ID, 400},
		{"NoReceptions", employeeToken, mock.PVZ.ID, 400},
		{"Closed", employeeToken, mock.PvzClosed.ID, 400},
		{"NotFound", employeeToken, uuid.NewString(), 400},
		{"Wrong", employeeToken, "123", 400},
		{"Empty", employeeToken, "", 301},
	}

	for _, tt := range tests {
		t.Run(tt.test, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req, _ := http.NewRequest(
				"POST", "/pvz/"+tt.pvzID+"/delete_last_product", nil)

			req.Header.Add("Authorization", "Bearer "+tt.auth)

			r.ServeHTTP(rec, req)

			if rec.Code != tt.code {
				t.Errorf("%s: want code %d, got code %d", tt.pvzID, tt.code, rec.Code)
			}
		})
	}
}

func TestGetSummary(t *testing.T) {
	startDate := url.QueryEscape(time.Now().Add(1 * time.Minute).Format(time.RFC3339))
	endDate := url.QueryEscape(time.Now().Add(-1 * time.Minute).Format(time.RFC3339))

	tests := []struct {
		test  string
		auth  string
		query string
		code  int
		count int
	}{
		{"Guest", guestToken, "", 403, 0},
		{"Moderator", employeeToken, "", 200, 5},
		{"Moderator", moderatorToken, "", 200, 5},
		{"Page", employeeToken, "?page=2", 200, 0},
		{"MinPage", employeeToken, "?page=0", 200, 5},
		{"MaxPage", moderatorToken, "?page=100", 200, 0},
		{"WrongPage", employeeToken, "?page=one", 200, 5},
		{"Limit", moderatorToken, "?limit=3", 200, 3},
		{"MinLimit", moderatorToken, "?limit=0", 200, 1},
		{"MaxLimit", employeeToken, "?limit=100", 200, 5},
		{"WrongLimit", moderatorToken, "?limit=ten", 200, 5},
		{"PageLimit", employeeToken, "?page=2&limit=3", 200, 2},
		{"StartDate", moderatorToken, "?startDate=" + startDate, 200, 0},
		{"EndDate", employeeToken, "?endDate=" + endDate, 200, 0},
		{"BothDates", moderatorToken, "?startDate=" + startDate + "&endDate=" + endDate, 200, 0},
		{"WrongStartDate", moderatorToken, "?startDate=yesterday", 200, 5},
		{"WrongEndDate", moderatorToken, "?endDate=tomorrow", 200, 5},
	}

	for _, tt := range tests {
		t.Run(tt.test, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req, _ := http.NewRequest(
				"GET", "/"+tt.query, nil)

			req.Header.Add("Authorization", "Bearer "+tt.auth)

			r.ServeHTTP(rec, req)

			var results []model.PVZResult
			json.NewDecoder(rec.Body).Decode(&results)
			count := len(results)

			if rec.Code != tt.code {
				t.Errorf("%s: want code %d, got code %d", "/"+tt.query, tt.code, rec.Code)
			}
			if count != tt.count {
				t.Errorf("%s: want count %d, got count %d", "/"+tt.query, tt.count, count)
			}
		})
	}
}
