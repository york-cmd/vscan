package yonyou

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)
//用友 uapws/index.jsp 控制台绕过漏洞


func Uapws(u string) bool {
	if req, err := pkg.HttpRequset(u+"/uapws/", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "basictable") && strings.Contains(req.Body, "<title>WS-Console</title>") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln yonyou uapws|%s\n", u+"/uapws/index.jsp"))
			return true
		}
	}
	return false
}