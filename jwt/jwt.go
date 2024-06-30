package jwt

import (
	"errors"
	"github.com/axiomatrix-org/toolchain/redis"
	"github.com/gin-gonic/gin"
	"gopkg.in/dgrijalva/jwt-go.v3"
	"net/http"
	"strings"
	"time"
)

// token claims
type TokenClaims struct {
	username string `json:"username"`
	role     string `json:"role"`
	exp      int    `json:"exp"`
	jwt.StandardClaims
}

// token secret
const SECRET = "ROMANCETILLDEATH"

// token err code
const (
	ErrCodeMalformed    = 1001
	ErrCodeExpired      = 1002
	ErrCodeNotValidYet  = 1003
	ErrCodeInvalidToken = 1004
	ErrCodeInvalidRole  = 1005
)

type TokenError struct {
	code    int
	message string
	exp     int
}

func (e *TokenError) Error() string {
	return e.message
}

// token generator
func GenToken(username string, role string, exp int) (string, error) {
	c := TokenClaims{
		username: username,
		role:     role,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(exp)).Unix(),
			Issuer:    "org.axiomatrix.toolchain",
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	str, err := token.SignedString([]byte(SECRET))
	if err != nil {
		return "", err
	}
	if !redis.SetRedisClient() {
		redis.SetValue(str, str, exp*60)
	} else {
		return "", errors.New("no redis connections")
	}
	return str, nil
}

func ParseToken(tokenString string, role string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(SECRET), nil
	})
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, &TokenError{code: ErrCodeMalformed, message: "Token is malformed"}
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				return nil, &TokenError{code: ErrCodeExpired, message: "Token is expired"}
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return nil, &TokenError{code: ErrCodeNotValidYet, message: "Token is not yet valid"}
			} else {
				return nil, &TokenError{code: ErrCodeInvalidToken, message: "Token is invalid"}
			}
		}
		return nil, err
	}

	if claims, ok := token.Claims.(*TokenClaims); ok && token.Valid {
		if claims.role == role {
			return claims, nil
		} else {
			return nil, &TokenError{code: ErrCodeInvalidRole, message: "Invalid role"}
		}
	}

	return nil, errors.New("invalid token")
}

func JWTAuthMiddleware(role string) func(c *gin.Context) {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"code": 4007,
				"msg":  "No Authorization header",
			})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			c.JSON(http.StatusBadRequest, gin.H{
				"code": 4008,
				"msg":  "Wrong Authorization header",
			})
			c.Abort()
			return
		}

		mc, err := ParseToken(parts[1], role)
		if err != nil {
			if TokenError, ok := err.(*TokenError); ok {
				switch TokenError.code {
				case ErrCodeMalformed:
					c.JSON(http.StatusBadRequest, gin.H{
						"code": 4001,
						"msg":  "Malformed token",
					})
					c.Abort()
					return
				case ErrCodeExpired:
					refreshHeader := c.Request.Header.Get("Refresh-Token")
					if refreshHeader == "" {
						c.JSON(http.StatusBadRequest, gin.H{
							"code": 4002,
							"msg":  "Token expired and refresh token not set",
						})
						c.Abort()
						return
					}
					mt, err := ParseToken(refreshHeader, role)
					if err != nil {
						c.JSON(http.StatusBadRequest, gin.H{
							"code": 4002,
							"msg":  "Token expired and refresh token is wrong",
						})
						c.Abort()
						return
					}
					token, err := GenToken(mt.username, mt.role, TokenError.exp)
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{
							"code": 500,
							"msg":  "Internal server error",
						})
						return
					}
					refresh, err := GenToken(mt.username, mt.role, mt.exp)
					c.Writer.Header().Set("Refresh-Token", refresh)
					c.Writer.Header().Set("Access-Token", token)
					c.Set("username", mc.username)
					c.Set("role", mc.role)
					c.Next()
					return
				case ErrCodeNotValidYet:
					c.JSON(http.StatusBadRequest, gin.H{
						"code": 4003,
						"msg":  "Not valid token",
					})
					c.Abort()
					return
				case ErrCodeInvalidToken:
					c.JSON(http.StatusBadRequest, gin.H{
						"code": 4004,
						"msg":  "Invalid token",
					})
					c.Abort()
					return
				case ErrCodeInvalidRole:
					c.JSON(http.StatusBadRequest, gin.H{
						"code": 4005,
						"msg":  "Invalid role",
					})
					c.Abort()
					return
				}
			}
		}
		c.Set("username", mc.username)
		c.Set("role", mc.role)
		c.Next()
	}
}
