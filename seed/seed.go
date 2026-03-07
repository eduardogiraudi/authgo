package seed

import (
	"auth/passwords"
	"context"
	"fmt"
	"os"
	"time"
	"auth/db"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
    "encoding/json"
    "go.mongodb.org/mongo-driver/bson/primitive"
)
type ClientData struct {
    ClientID            string   `json:"client_id" bson:"client_id"`
    AuthorizedRedirects []string `json:"authorized_redirects" bson:"authorized_redirects"`
    ClientSecret        string   `json:"client_secret" bson:"client_secret"`
    OwnerID             primitive.ObjectID `json:"-" bson:"owner_id"`
}
func SeedTestUser() {
    collection := db.MongoDB.Collection("users")
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    var existingUser bson.M
    err := collection.FindOne(ctx, bson.M{"username": "demo"}).Decode(&existingUser)
    
    if err == nil {
    	fmt.Printf("Seed user already exists. Skipping generation\n")
        return
    }

    if err != mongo.ErrNoDocuments {
        fmt.Printf("Error during the check if the seed user exists: %v\n", err)
        return
    }

    password := "demo" 
    hash, err := passwords.GenerateHash(password)
    if err != nil {
        fmt.Printf("Error during hashing seed: %v\n", err)
        return
    }

    newUser := bson.M{
        "username": "demo",
        "password": hash,
        "email":    "demo@demo.com",
    }

    _, err = collection.InsertOne(ctx, newUser)
    if err != nil {
        fmt.Printf("Error during inserting seed user: %v\n", err)
        return
    }

    fmt.Println("Seed user 'demo' created successfully.")
}

func SeedTestClient() {
    collection := db.MongoDB.Collection("clients") // Assicurati che la collection sia "clients"
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    file, err := os.ReadFile("client.json")
    if err != nil {
        fmt.Printf("Error during reading client.json: %v\n", err)
        return
    }

    var clientData ClientData
    if err := json.Unmarshal(file, &clientData); err != nil {
        fmt.Printf("Error during the parse of client.json: %v\n", err)
        return
    }

    var existingClient bson.M
    err = collection.FindOne(ctx, bson.M{"client_id": clientData.ClientID}).Decode(&existingClient)

    if err == nil {
        fmt.Printf("Seed client '%s' already exists. Skipping...\n", clientData.ClientID)
        return
    }

    if err != mongo.ErrNoDocuments {
        fmt.Printf("Error during the check of the seed client: %v\n", err)
        return
    }
    var demoUser bson.M
    err = db.MongoDB.Collection("users").FindOne(ctx, bson.M{"username": "demo"}).Decode(&demoUser)
    if err != nil {
        fmt.Printf("Errore: no demo users found to create client ownership.\n")
        return
    }
    if oid, ok := demoUser["_id"].(primitive.ObjectID); ok {
    clientData.OwnerID = oid
    } else {
        fmt.Println("Errore: cannot retrieve user id of demo user. Skipping client generation\n")
        return
    }
    secret,error:=passwords.GenerateHash(clientData.ClientSecret)
    if error !=nil{
        fmt.Printf("Error during hashing client_secret of seed client: %v\n", error)
        return
    }
    clientData.ClientSecret = secret
    _, err = collection.InsertOne(ctx, clientData)
    if err != nil {
        fmt.Printf("Error during the insertion of seed client: %v\n", err)
        return
    }

    fmt.Printf("Seed client '%s' created successfully.\n", clientData.ClientID)
}