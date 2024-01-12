package infra

import (
	"github.com/spf13/viper"
)

var (
	Conf *viper.Viper

	AccessKey string
	SecretKey string

	ApiAuth                   bool
	RbacUrl                   string
	GetSessionValidityTimeUrl string
	BusinessType              string
	InnerAuth                 map[string]string
	Secret                    string

	SvrAK string
	SvrSK string

	SdAK string
	SdSK string

	ConfPath string
)
