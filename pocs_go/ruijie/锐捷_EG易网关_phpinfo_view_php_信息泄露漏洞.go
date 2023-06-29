package ruijie

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func Ruijie_EG(url string) bool {
	if req, err := pkg.HttpRequset(url+"/tool/view/phpinfo.view.php", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "RUIJIE_UPLOAD_PROGRESS") && strings.Contains(req.Body, "RUIJIEID") {
			pkg.GoPocLog(fmt.Sprintf("锐捷_EG易网关_phpinfo.view.php_信息泄露漏洞|%s\n", url))
			return true
		}
	}
	return false
}
