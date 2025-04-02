package main

import (
	"server/core"
	"server/global"
	"server/initialize"
)

func main() {
	global.Config = core.InitConf()
	global.Log = core.InitLogger()
	global.DB = initialize.InitGorm()
	global.Redis = initialize.ConnectRedis()
	defer global.Redis.Close()
	global.ESClient = initialize.ConnectES()
	initialize.OtherInit()
	initialize.InitCron()

	core.RunServer()
}
