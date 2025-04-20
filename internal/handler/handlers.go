package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/greg-frost/go-avito/internal/model"
	"github.com/greg-frost/go-avito/internal/storage"
	u "github.com/greg-frost/go-avito/internal/utils"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type handler struct {
	storage storage.Storage
}

func NewHandler(storage storage.Storage) Handler {
	return &handler{storage: storage}
}

func (h *handler) Register(router *mux.Router) {
	router.HandleFunc("/dummyLogin", h.DummyLogin).Methods("POST")
	router.HandleFunc("/pvz", h.CreatePVZ).Methods("POST")
	router.HandleFunc("/receptions", h.CreateReception).Methods("POST")
	router.HandleFunc("/pvz/{pvzId}/close_last_reception", h.CloseLastReception).Methods("POST")
	router.HandleFunc("/products", h.CreateProduct).Methods("POST")
	router.HandleFunc("/pvz/{pvzId}/delete_last_product", h.DeleteLastProduct).Methods("POST")
	router.HandleFunc("/", h.GetSummary).Methods("GET")
}

func (h *handler) DummyLogin(w http.ResponseWriter, r *http.Request) {
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

func (h *handler) CreatePVZ(w http.ResponseWriter, r *http.Request) {
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

	if err := h.storage.CreatePVZ(newPVZ); err != nil {
		log.Println("pvz insert error:", err)
		u.RespondWithError(w, model.Error{
			Code:    http.StatusInternalServerError,
			Message: "pvz was not created",
		})
		return
	}

	u.Respond(w, http.StatusCreated, newPVZ)
}

func (h *handler) CreateReception(w http.ResponseWriter, r *http.Request) {
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

	if _, err := h.storage.FindPVZ(pvzID); err != nil {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "pvz not found",
		})
		return
	}

	lastReception, _ := h.storage.FindLastReception(pvzID)
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

	if err := h.storage.CreateReception(newReception); err != nil {
		log.Println("reception insert error:", err)
		u.RespondWithError(w, model.Error{
			Code:    http.StatusInternalServerError,
			Message: "reception was not created",
		})
		return
	}

	u.Respond(w, http.StatusCreated, newReception)
}

func (h *handler) CloseLastReception(w http.ResponseWriter, r *http.Request) {
	role := u.GetRoleFromContext(r.Context())
	if role != model.RoleEmployee {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusForbidden,
			Message: "only for employees",
		})
		return
	}

	pvzID := mux.Vars(r)["pvzId"]

	lastReception, _ := h.storage.FindLastReception(pvzID)
	if lastReception.Status != model.StatusInProgress {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "no reception in progress",
		})
		return
	}

	if err := h.storage.CloseReception(lastReception.ID); err != nil {
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

func (h *handler) CreateProduct(w http.ResponseWriter, r *http.Request) {
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

	lastReception, _ := h.storage.FindLastReception(pvzID)
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

	if err := h.storage.CreateProduct(newProduct); err != nil {
		log.Println("product insert error:", err)
		u.RespondWithError(w, model.Error{
			Code:    http.StatusInternalServerError,
			Message: "product was not created",
		})
		return
	}

	u.Respond(w, http.StatusCreated, newProduct)
}

func (h *handler) DeleteLastProduct(w http.ResponseWriter, r *http.Request) {
	role := u.GetRoleFromContext(r.Context())
	if role != model.RoleEmployee {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusForbidden,
			Message: "only for employees",
		})
		return
	}

	pvzID := mux.Vars(r)["pvzId"]

	lastReception, _ := h.storage.FindLastReception(pvzID)
	if lastReception.Status != model.StatusInProgress {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "no reception in progress",
		})
		return
	}

	lastProduct, err := h.storage.FindLastProduct(lastReception.ID)
	if err != nil {
		u.RespondWithError(w, model.Error{
			Code:    http.StatusBadRequest,
			Message: "no products to delete",
		})
		return
	}

	if err := h.storage.DeleteProduct(lastProduct.ID); err != nil {
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

func (h *handler) GetSummary(w http.ResponseWriter, r *http.Request) {
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

	pvzs, err := h.storage.ListPVZ(page, limit, startDate, endDate, filterByDate)
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

	receptions, err := h.storage.ListReceptions(pvzIDs, startDate, endDate)
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

	products, err := h.storage.ListProducts(receptionsIDs)
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
