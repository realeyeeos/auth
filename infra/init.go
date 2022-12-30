package infra

import (
	"flag"
	"fmt"
	"github.com/realeyeeos/auth/infra/userconfig"
	"github.com/realeyeeos/auth/infra/ylog"
	"os"
)

func init() {
	confPath := flag.String("authConfig", "conf/auth.yml", "ConfigPath")
	flag.Parse()
	ConfPath = *confPath

	InitConfig()
}

func initlog() {
	logger := ylog.NewYLog(
		ylog.WithLogFile(Conf.GetString("log.path")),
		ylog.WithMaxAge(3),
		ylog.WithMaxSize(10),
		ylog.WithMaxBackups(3),
		ylog.WithLevel(Conf.GetInt("log.loglevel")),
	)
	ylog.InitLogger(logger)
}

func initDefault() {

	ApiAuth = Conf.GetBool("auth.apiauth.enable")
	RbacUrl = Conf.GetString("auth.rbac.url")

}

func InitConfig() {
	var (
		err error
	)
	//load config
	if Conf, err = userconfig.NewUserConfig(userconfig.WithPath(ConfPath)); err != nil {
		fmt.Println("NEW_CONFIG_ERROR", err.Error())
		os.Exit(-1)
	}
	initlog()
	initDefault()
}
