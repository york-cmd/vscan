package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

// 泛微 E-office 存在未授权访问

func E_Coloy_UserSelect_unauthorized(u string) bool {
	if req, err := pkg.HttpRequset(u+"/UserSelect/", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "/UserSelect/top.php") && strings.Contains(req.Body, "/UserSelect/main.php") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln weaver UserSelect 未授权访问|%s\n", u+"/UserSelect/"))

			return true
		}
	}
	return false
}
