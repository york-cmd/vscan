package seeyon
import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//A8 authorityService?wsdl 任意用户密码修改

func AuthorItyService(u string) bool {
	if req, err := pkg.HttpRequset(u+"/seeyon/services/authorityService?wsdl", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "userName") && strings.Contains(req.Body, "password") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln seeyon authorityService?wsdl|%s\n", u+"/seeyon/services/authorityService?wsdl"))
			
			return true
		}
	}
	return false
}
