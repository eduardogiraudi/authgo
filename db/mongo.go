package db

import (
	"context"
	"fmt"
	"os"
	"time"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var MongoClient *mongo.Client
var MongoDB *mongo.Database

func ConnectMongo() {
    uri := os.Getenv("MONGO_URI")
    dbName := os.Getenv("MONGO_DATABASE")
    user := os.Getenv("MONGO_USER")
    pass := os.Getenv("MONGO_PASS")

    if uri == "" {
        uri = "mongodb://localhost:27017"
    }

    clientOptions := options.Client().ApplyURI(uri)

    if user != "" && pass != "" {
        credential := options.Credential{
            AuthSource: "admin", 
            Username:   user,
            Password:   pass,
        }
        clientOptions.SetAuth(credential)
    } 

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    client, err := mongo.Connect(ctx, clientOptions)
    if err != nil {
        fmt.Printf("Critical error (mongodb): %v\n", err)
        return
    }

    err = client.Ping(ctx, nil)
    if err != nil {
        fmt.Printf("Cannot connect MongoDB: %v\n", err)
    } else {
        fmt.Println("Connected to MongoDB server")
    }

    MongoClient = client
    MongoDB = client.Database(dbName)
}