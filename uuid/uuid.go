package uuid

import (
	"math/rand"
	"time"
)

func GenerateRandomDigits(length int) string {
	const digits = "0123456789"
	result := make([]byte, length)
	rand.Seed(time.Now().UnixNano())
	for i := range result {
		result[i] = digits[rand.Intn(len(digits))]
	}
	return string(result)
}
