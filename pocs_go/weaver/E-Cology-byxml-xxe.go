package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"

	"strings"
)

func E_Cology_byxml_xxe(u string) bool {

	if req, err := pkg.HttpRequset(u+"/rest/ofs/deleteUserRequestInfoByXml", "GET", "", false, nil); err == nil {

		if req.StatusCode == 200 && strings.Contains(req.Body, "WfData") && strings.Contains(req.Body, "ResultInfo") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln E_Cology_byxml_xxe|%s\n", u+"/rest/ofs/deleteUserRequestInfoByXml"))
			return true
		}
	}

	return false
}
