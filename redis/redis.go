package redis

import (
	"fmt"
	"github.com/go-redis/redis"
	"strconv"
	"time"
)

var client *redis.Client

type ClientOptions struct {
	addr     string
	port     int
	password string
	db       int
}

type Options func(*ClientOptions)

func WithAddr(addr string) Options {
	return func(o *ClientOptions) {
		o.addr = addr
	}
}

func WithPort(port int) Options {
	return func(o *ClientOptions) {
		o.port = port
	}
}

func WithPassword(password string) Options {
	return func(o *ClientOptions) {
		o.password = password
	}
}

func WithDB(db int) Options {
	return func(o *ClientOptions) {
		o.db = db
	}
}

// 初始化redis連結
func SetRedisClient(opt ...Options) bool {
	if client != nil {
		return false
	}
	clientOptions := &ClientOptions{
		addr:     "127.0.0.1",
		port:     6379,
		password: "",
		db:       0,
	}

	for _, o := range opt {
		o(clientOptions)
	}

	client = redis.NewClient(&redis.Options{
		Addr:     clientOptions.addr + ":" + strconv.Itoa(clientOptions.port),
		Password: clientOptions.password,
		DB:       clientOptions.db,
	})

	return true
}

// 存儲文字資料
func SetValue(key string, value string, exp int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println("Recovered in f", r)
		}
	}()

	err := client.Set(key, value, time.Duration(exp)*time.Second).Err()
	if err != nil {
		panic(err)
	}
}

// 獲取文字資料
func GetValue(key string) (string, error) {
	result, err := client.Get(key).Result()
	if err != nil {
		return "", err
	}
	return result, nil
}
