package rate

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"sync"
	"time"
)

type rateLimiter struct {
	visitors map[string]*visitor
	mu       sync.Mutex
	rate     int
}

type visitor struct {
	limiter  *time.Ticker
	lastSeen time.Time
}

func newRateLimiter(rate int) *rateLimiter {
	rl := &rateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
	}
	go rl.cleanupVisitors()
	return rl
}

func (rl *rateLimiter) getVisitor(ip string) *time.Ticker {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		limiter := time.NewTicker(time.Second / time.Duration(rl.rate))
		rl.visitors[ip] = &visitor{limiter, time.Now()}
		return limiter
	}
	v.lastSeen = time.Now()
	return v.limiter
}

func (rl *rateLimiter) cleanupVisitors() {
	for {
		time.Sleep(time.Minute)
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(rl.visitors, ip)
				v.limiter.Stop()
			}
		}
		rl.mu.Unlock()
	}
}

func rateLimitMiddleware(rl *rateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		limiter := rl.getVisitor(ip)

		select {
		case <-limiter.C:
			// Allow request
		default:
			// Too many requests
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "TOO MANY REQUESTS"})
			return
		}
		c.Next()
	}
}
