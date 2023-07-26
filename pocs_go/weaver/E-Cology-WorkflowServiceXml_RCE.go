package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

// 泛微 OA WorkflowServiceXml RCE
// Fofa:  app="泛微-协同办公OA"

func E_Cology_WorkflowServiceXml_rce(u string) bool {
	url := u + "/services%20/WorkflowServiceXml"
	if req, err := pkg.HttpRequset(url, "GET", "", false, nil); err == nil {
		if req.StatusCode != 0 && req.StatusCode != 404 && strings.Contains(req.Body, "Invalid SOAP request") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln WorkflowServiceXml_rce|%s\n", url))

			return true
		}
	}
	return false
}
