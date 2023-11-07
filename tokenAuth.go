package auth

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"github.com/realeyeeos/auth/infra"
	"github.com/realeyeeos/auth/infra/ylog"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var whiteUrlList = []string{"/eos-service/api/v1/user/login",
	"/eos-service/api/v1/agent/subTask/updateSubTask",
	"/eos-service/api/v1/agent/queryInfo",
	"/eos-service/api/v6/systemRouter/InsertAlert",
	"/eos-service/api/v1/downloader/getNewestVersion"}

type AuthClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func CreateToken(payload jwt.Claims, secret []byte) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)

	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func VerifyToken(tokenString string, secret []byte) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("parser failed")
		}

		return secret, nil
	})

	if err != nil {
		ylog.Errorf("VerifyToken", err.Error())
		ylog.Errorf("Token failed", tokenString)
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return &claims, nil
	}
	return nil, errors.New("verify token failed")
}

func checkPassword(password, salt, hash string) bool {
	t := sha1.New()
	io.WriteString(t, password+salt)
	if fmt.Sprintf("%x", t.Sum(nil)) == hash {
		return true
	}
	return false
}

func GenPassword(password, salt string) string {
	t := sha1.New()
	io.WriteString(t, password+salt)
	return fmt.Sprintf("%x", t.Sum(nil))
}

func CheckUser(username, password, salt, hash string) (string, error) {
	if !checkPassword(password, salt, hash) {
		return "", errors.New("verify password failed")
	}

	tokenString, err := CreateToken(
		AuthClaims{
			Username: username,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(120 * time.Minute)),
			},
		},
		[]byte(infra.Secret),
	)
	return tokenString, err
}

func TokenAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !infra.ApiAuth {
			c.Next()
			return
		}

		//whitelist
		if strings.HasPrefix(c.Request.URL.Path, "/eos-service/api/v1/agent/getConfig/") {
			c.Next()
			return
		}

		//url_whitelist
		if infra.Contains(whiteUrlList, c.Request.URL.Path) {
			c.Next()
			return
		}

		token := c.GetHeader("token")
		if token == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		payload, err := VerifyToken(token, []byte(infra.Secret))
		if err != nil {
			ylog.Errorf("AuthRequired", err.Error())
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if payload == nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		currentUser, ok := (*payload)["username"]
		if currentUser == "" || !ok {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if int64((*payload)["exp"].(float64)) < time.Now().Add(20*time.Minute).Unix() {
			tokenString, err := CreateToken(
				AuthClaims{
					Username: currentUser.(string),
					RegisteredClaims: jwt.RegisteredClaims{
						ExpiresAt: jwt.NewNumericDate(time.Now().Add(120 * time.Minute)),
					},
				},
				[]byte(infra.Secret),
			)
			if err != nil {
				ylog.Errorf("AuthRequired", err.Error())
			} else {
				c.Header("token", tokenString)
			}
		}
		c.Header("user", currentUser.(string))
		c.Set("user", currentUser.(string))
		c.Next()
		return
	}
}
