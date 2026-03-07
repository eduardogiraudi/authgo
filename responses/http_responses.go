package responses

import (
	"encoding/json"
	"net/http"
	"fmt"
)

type ErrorResponse struct {
	Error string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func sendJSONResponse(w http.ResponseWriter, statusCode int, payload interface{}, noCache bool) {
	w.Header().Set("Content-Type", "application/json")
	if noCache {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
	}
	
	w.WriteHeader(statusCode)
	if statusCode!=200{
		fmt.Printf("%v - %v\n",payload, statusCode)
	}else {
		fmt.Printf("%v\n", statusCode)
	}
	json.NewEncoder(w).Encode(payload)
}

func BadRequest(w http.ResponseWriter, err string, descr string) {
	sendJSONResponse(w, http.StatusBadRequest, ErrorResponse{err, descr}, true)
}

func NotFound(w http.ResponseWriter, err string, descr string) {
	sendJSONResponse(w, http.StatusNotFound, ErrorResponse{err, descr}, true)
}

func Unauthorized(w http.ResponseWriter, err string, descr string) {
	sendJSONResponse(w, http.StatusUnauthorized, ErrorResponse{err, descr}, true)
}

func Forbidden(w http.ResponseWriter, descr string) {
	sendJSONResponse(w, http.StatusForbidden, ErrorResponse{"forbidden", descr}, true)
}

func TemporarilyUnavailable(w http.ResponseWriter, descr string) {
	sendJSONResponse(w, http.StatusServiceUnavailable, ErrorResponse{"temporarily_unavailable", descr}, true)
}

func ServerError(w http.ResponseWriter) {
	sendJSONResponse(w, http.StatusInternalServerError, ErrorResponse{"server_error", "Internal server error"}, true)
}

func OK(w http.ResponseWriter, data interface{}) {
	payload := map[string]interface{}{"message": data}
	sendJSONResponse(w, http.StatusOK, payload, false)
}