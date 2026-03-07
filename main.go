package main

import (
	"auth/cryptokeys"
	"auth/db"
	"auth/jwts"
	"auth/routes"
	"auth/seed"
	"fmt"
	"github.com/joho/godotenv"
	"net/http"
	"os"
)

func main() {
	env := godotenv.Load()
	if env != nil {
		fmt.Println("No .env found")
	}
	if os.Getenv("PEPPER") == "" {
		fmt.Println("PEPPER not set\n")
	}
	cryptokeys.GenKeys(false)
	if err := jwts.Init(); err != nil {
		fmt.Printf("Error: %s\n", err)
	}
	db.ConnectRedis()
	db.ConnectMongo()
	seed.SeedTestUser()
	seed.SeedTestClient()

	mux := http.NewServeMux()
	routes.SetupRoutes(mux)

	corsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://localhost:5173")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, DPoP")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		mux.ServeHTTP(w, r)
	})

	fmt.Println("Server listening to http://localhost:8010")

	err := http.ListenAndServe(":"+os.Getenv("PORT"), corsHandler)
	if err != nil {
		fmt.Printf("Server boot error: %s\n", err)
	}
}