package auth

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

const (
	SuccessCode = iota
	AuthFailedErrorCode
	DuplicateFieldErrorCode
	DBOperateErrorCode
	RedisOperateErrorCode
	ParamInvalidErrorCode
	DBNoRowAffectedErrorCode
	TemporarilyUnavailable
	ErrorIDLen
	ErrorID
	UnknownErrorCode
	TimeOutErrorCode
	RemoteAllFailedErrorCode
	ProjectIDRespect
	SomeFieldIsNull
)

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"msg"`
	Data    interface{} `json:"data"`
}

func (response *Response) SetError(code int) {
	response.Code = code

	if msg, ok := ErrorDescriptions[code]; ok {
		response.Message = msg
	}
}

var ErrorDescriptions = map[int]string{
	SuccessCode:              "success",
	AuthFailedErrorCode:      "auth failed",
	DuplicateFieldErrorCode:  "duplicate field",
	DBOperateErrorCode:       "db operate error",
	RedisOperateErrorCode:    "redis operate error",
	ParamInvalidErrorCode:    "param invalid",
	DBNoRowAffectedErrorCode: "db no row affected",
	TemporarilyUnavailable:   "resource temporarily unavailable",
	ErrorIDLen:               "ID MAX LEN IS 1-15",
	ErrorID:                  "ID ONLY SYUUPRT 'A-Z/a-z/0-9/-/_'",
	UnknownErrorCode:         "unknown error",
	ProjectIDRespect:         "PROJECT ID REPECT",
	SomeFieldIsNull:          "SOME FIELD IS NUL",
	TimeOutErrorCode:         "get result timeout",
	RemoteAllFailedErrorCode: "all remote instance failed",
}

func CreateResponse(c *gin.Context, code int, data interface{}) {
	var response Response

	response.SetError(code)
	response.Data = data
	c.JSON(
		http.StatusOK,
		response,
	)
}
