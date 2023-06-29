package sanhui

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func Sanhui(url string) bool {
	if req, err := pkg.HttpRequset(url+"/debug.php", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "function") {
			pkg.GoPocLog(fmt.Sprintf("三汇SMG_网关管理软件_down.php_任意文件读取漏洞|%s\n", url))
			return true
		}
	}
	return false
}
