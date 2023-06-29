package yonyou

import (
	"fmt"
	"github.com/veo/vscan/pkg"
)
//用友 GRP-u8 FileReceiveServlet 任意文件上传漏洞


func FileReceiveServlet(u string) bool {


	if req, err := pkg.HttpRequset(u+"/servlet/FileReceiveServlet", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && req.Header.Get("Set-Cookie") != ""{
			pkg.GoPocLog(fmt.Sprintf("Found may be vuln yonyou FileReceiveServlet-rce |%s\n", u+"/servlet/FileReceiveServlet"))
			return true
		}
	}
	return false
}