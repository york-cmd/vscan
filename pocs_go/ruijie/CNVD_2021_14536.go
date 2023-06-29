package ruijie

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func CNVD_2021_14536(url string) bool {
	if req, err := pkg.HttpRequset(url+"", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "super_admin") && strings.Contains(req.Body, "guest_admin") {
			pkg.GoPocLog(fmt.Sprintf("锐捷-RG-UAC-账号密码信息泄露-CNVD-2021-14536|%s\n", url))
			return true
		}
	}
	return false
}
