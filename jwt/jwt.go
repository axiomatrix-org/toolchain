package jwt

import (
	"errors"
	"github.com/axiomatrix-org/toolchain/redis"
	"github.com/gin-gonic/gin"
	"gopkg.in/dgrijalva/jwt-go.v3"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// token claims
type TokenClaims struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	Exp   int    `json:"exp"`
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

const (
	ROOTROLE  = 4
	ADMINROLE = 3
	USERROLE  = 2
	TEMPROLE  = 1
)

var (
	ACCESS_TIME  = 1440
	REFRESH_TIME = 2160
)

type TokenError struct {
	code    int
	message string
	exp     int
}

func (e *TokenError) Error() string {
	return e.message
}

func claimToRole(claim string) int {
	switch claim {
	case "root":
		return ROOTROLE
	case "admin":
		return ADMINROLE
	case "user":
		return USERROLE
	case "temp":
		return TEMPROLE
	default:
		return 0
	}
}

func SetTime(access_time int, refresh_time int) {
	ACCESS_TIME = access_time
	REFRESH_TIME = refresh_time
}

// token generator
func GenToken(email string, role string, exp int) (string, error) {
	key := email + strconv.FormatInt(time.Now().UnixMilli(), 10)
	c := TokenClaims{
		Email: key,
		Role:  role,
		Exp:   exp,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Minute * time.Duration(exp)).Unix(),
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
		redis.SetValue(key, str, exp*60)
	} else {
		return "", errors.New("no redis connections")
	}
	time.Sleep(time.Duration(2) * time.Millisecond)
	return str, nil
}

func ParseToken(tokenString string, role int) (*TokenClaims, error) {
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
		if !redis.SetRedisClient() {
			str, err := redis.GetValue(claims.Email)
			if str == "" {
				return nil, &TokenError{code: ErrCodeExpired, message: "Token is expired"}
			} else if str != tokenString {
				return nil, &TokenError{code: ErrCodeInvalidToken, message: "Token is invalid"}
			}
			if err != nil {
				return nil, err
			}
		} else {
			return nil, errors.New("no redis connections")
		}

		if claimToRole(claims.Role) >= role {
			if claims.Role == "temp" { // temp級別的token只用來註冊，一經註冊即刻滅活
				_, err := Kickoff(claims.Email)
				if err != nil {
					return nil, err
				}
			}
			return claims, nil
		} else {
			return nil, &TokenError{code: ErrCodeInvalidRole, message: "Invalid role"}
		}
	}

	return nil, errors.New("invalid token")
}

// 滅活token
func Kickoff(email string) (bool, error) {
	if !redis.SetRedisClient() {
		str, err := redis.GetValue(email)
		if err != nil {
			return false, err
		}

		if str == "" {
			return false, errors.New("invalid token")
		}

		redis.DeleteValue(email)
		return true, nil
	} else {
		return false, errors.New("no redis connections")
	}
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

		claims, err := ParseToken(parts[1], claimToRole(role))
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
					mt, err := ParseToken(refreshHeader, claimToRole(role))
					if err != nil {
						c.JSON(http.StatusBadRequest, gin.H{
							"code": 4002,
							"msg":  "Token expired and refresh token is wrong",
						})
						c.Abort()
						return
					}
					token, err := GenToken(mt.Email, mt.Role, ACCESS_TIME)
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{
							"code": 500,
							"msg":  "Internal server error",
						})
						return
					}
					refresh, err := GenToken(mt.Email, mt.Role, REFRESH_TIME)
					c.Writer.Header().Set("Refresh-Token", refresh)
					c.Writer.Header().Set("Access-Token", token)
					c.Set("email", claims.Email)
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
				default:
					c.JSON(http.StatusInternalServerError, gin.H{
						"code":    500,
						"message": TokenError,
					})
				}
			}
		}
		c.Set("email", claims.Email)
		c.Next()
	}
}
