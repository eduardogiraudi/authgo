package routes

import (
	"encoding/json"
	"net/http"
	"os"
	"auth/responses"
	"github.com/altcha-org/altcha-lib-go"
	"time"
)
func GetCaptchaChallenge(w http.ResponseWriter, r *http.Request) {
	secret := os.Getenv("ALTCHA_HMAC_KEY")
	expiry := time.Now().Add(2 * time.Minute)

	options := altcha.ChallengeOptions{
		HMACKey:   secret,
		MaxNumber: 200000, 
		Expires:   &expiry,
	}

	challenge, err := altcha.CreateChallenge(options)
	if err != nil {
		responses.ServerError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(challenge)
}
