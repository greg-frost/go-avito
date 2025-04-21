package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/greg-frost/go-avito/internal/model"
)

var (
	employeeToken  string
	moderatorToken string
	guestToken     string
)

func init() {
	employee := model.Token{Role: model.RoleEmployee}
	employeeToken, _ = employee.SignedString()

	moderator := model.Token{Role: model.RoleModerator}
	moderatorToken, _ = moderator.SignedString()

	guest := model.Token{Role: "guest"}
	guestToken, _ = guest.SignedString()
}

func TestParseToken(t *testing.T) {
	tests := []struct {
		test    string
		header  string
		isError bool
	}{
		{"Employee", "Bearer " + employeeToken, false},
		{"Moderator", "Bearer " + moderatorToken, false},
		{"Guest", "Bearer " + guestToken, false},
		{"EmployeeWithoutBearer", employeeToken, true},
		{"ModeratorWithoutBearer", moderatorToken, true},
		{"MalformedCrop", "Bearer " + employeeToken[1:len(employeeToken)-1], true},
		{"MalformedExtend", "Bearer pre" + moderatorToken + "post", true},
		{"ThreeParts", "Super Bearer " + employeeToken, true},
		{"Invalid", "letMyIn!!!", true},
		{"Empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.test, func(t *testing.T) {
			_, err := ParseToken(tt.header)
			if isError := err != nil; isError != tt.isError {
				t.Errorf("%s: want error, got none", tt.header)
			}
		})
	}
}

func TestJwtAuthentication(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := http.Handler(JwtAuthentication(ok))

	tests := []struct {
		test   string
		method string
		path   string
		header string
		code   int
	}{

		{"DummyLogin", "POST", "/dummyLogin", "", 200},
		{"Register", "POST", "/register", "", 200},
		{"Login", "POST", "/login", "", 200},
		{"Employee", "GET", "/", "Bearer " + employeeToken, 200},
		{"Moderator", "GET", "/", "Bearer " + moderatorToken, 200},
		{"Guest", "GET", "/", "Bearer " + guestToken, 200},
		{"Forbidden", "GET", "/", "", 403},
	}

	for _, tt := range tests {
		t.Run(tt.test, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req, _ := http.NewRequest(tt.method, tt.path, nil)

			req.Header.Add("Authorization", tt.header)

			handler.ServeHTTP(rec, req)

			if rec.Code != tt.code {
				t.Errorf("%s: want code %d, got code %d", tt.path, tt.code, rec.Code)
			}
		})
	}
}
