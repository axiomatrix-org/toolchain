package rate

import (
	"github.com/gin-gonic/gin"
	"net/http"
	"sync"
	"time"
)

type RequestInfo struct {
	LastAccessTime time.Time
	RequestCount   int
}

var mutex = &sync.Mutex{}

type RateLimitConfig struct {
	maxRequests int
	timeWindow  time.Duration
	requestInfo map[string]*RequestInfo
}

func NewRateLimitConfig(maxRequests int, timeWindow time.Duration) *RateLimitConfig {
	return &RateLimitConfig{
		maxRequests: maxRequests,
		timeWindow:  timeWindow,
		requestInfo: make(map[string]*RequestInfo),
	}
}

func (r1 *RateLimitConfig) RateLimitMiddleware(c *gin.Context) {
	ip := c.ClientIP()
	mutex.Lock()
	defer mutex.Unlock()

	info, exists := r1.requestInfo[ip]

	if !exists {
		r1.requestInfo[ip] = &RequestInfo{LastAccessTime: time.Now(), RequestCount: 1}
		return
	}

	if time.Since(info.LastAccessTime) > r1.timeWindow {
		info.RequestCount = 1
		info.LastAccessTime = time.Now()
		return
	}

	info.RequestCount++

	if info.RequestCount > r1.maxRequests {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
		c.Abort()
		return
	}

	info.LastAccessTime = time.Now()
}
