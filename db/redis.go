package db

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"os"
)

var RDB *redis.Client

func ConnectRedis() {
	RDB = redis.NewClient(&redis.Options{
		Addr:	  os.Getenv("REDIS_ADDRESS")+":"+os.Getenv("REDIS_PORT"),
		Password: os.Getenv("REDIS_PASSWORD"), 
		DB:       0,
	})

	if err := RDB.Ping(context.Background()).Err(); err != nil {
		fmt.Println("Cannot connect to Redis: %v", err)
	}else{
		fmt.Println("Connected to Redis server")
	}
}