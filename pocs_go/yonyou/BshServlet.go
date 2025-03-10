package yonyou

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)
//用友 FE协作办公平台 templateOfTaohong_manager.jsp 目录遍历漏洞


func BshServlet(u string) bool {

	backurls := []string{"/servlet/~ic/bsh.servlet.BshServlet","/service/~aim/bsh.servlet.BshServlet","/service/~alm/bsh.servlet.BshServlet","/service/~ampub/bsh.servlet.BshServlet","/service/~arap/bsh.servlet.BshServlet","/service/~aum/bsh.servlet.BshServlet","/service/~cc/bsh.servlet.BshServlet","/service/~cdm/bsh.servlet.BshServlet","/service/~cmp/bsh.servlet.BshServlet","/service/~ct/bsh.servlet.BshServlet","/service/~dm/bsh.servlet.BshServlet","/service/~erm/bsh.servlet.BshServlet","/service/~fa/bsh.servlet.BshServlet","/service/~fac/bsh.servlet.BshServlet","/service/~fbm/bsh.servlet.BshServlet","/service/~ff/bsh.servlet.BshServlet","/service/~fip/bsh.servlet.BshServlet","/service/~fipub/bsh.servlet.BshServlet","/service/~fp/bsh.servlet.BshServlet","/service/~fts/bsh.servlet.BshServlet","/service/~fvm/bsh.servlet.BshServlet","/service/~gl/bsh.servlet.BshServlet","/service/~hrhi/bsh.servlet.BshServlet","/service/~hrjf/bsh.servlet.BshServlet","/service/~hrpd/bsh.servlet.BshServlet","/service/~hrpub/bsh.servlet.BshServlet","/service/~hrtrn/bsh.servlet.BshServlet","/service/~hrwa/bsh.servlet.BshServlet","/service/~ia/bsh.servlet.BshServlet","/service/~ic/bsh.servlet.BshServlet","/service/~iufo/bsh.servlet.BshServlet","/service/~modules/bsh.servlet.BshServlet","/service/~mpp/bsh.servlet.BshServlet","/service/~obm/bsh.servlet.BshServlet","/service/~pu/bsh.servlet.BshServlet","/service/~qc/bsh.servlet.BshServlet","/service/~sc/bsh.servlet.BshServlet","/service/~scmpub/bsh.servlet.BshServlet","/service/~so/bsh.servlet.BshServlet","/service/~so2/bsh.servlet.BshServlet","/service/~so3/bsh.servlet.BshServlet","/service/~so4/bsh.servlet.BshServlet","/service/~so5/bsh.servlet.BshServlet","/service/~so6/bsh.servlet.BshServlet","/service/~tam/bsh.servlet.BshServlet","/service/~tbb/bsh.servlet.BshServlet","/service/~to/bsh.servlet.BshServlet","/service/~uap/bsh.servlet.BshServlet","/service/~uapbd/bsh.servlet.BshServlet","/service/~uapde/bsh.servlet.BshServlet","/service/~uapeai/bsh.servlet.BshServlet","/service/~uapother/bsh.servlet.BshServlet","/service/~uapqe/bsh.servlet.BshServlet","/service/~uapweb/bsh.servlet.BshServlet","/service/~uapws/bsh.servlet.BshServlet","/service/~vrm/bsh.servlet.BshServlet","/service/~yer/bsh.servlet.BshServlet"}
	var vuln = false
	for _, backurl := range backurls {
		if req, err := pkg.HttpRequset(u+backurl, "GET", "", false, nil); err == nil {
			if req.StatusCode == 200 && (!strings.Contains(req.Body, "BeanShell") || strings.Contains(req.Body, "/servlet/~ic/bsh.servlet.BshServlet")) {
				pkg.GoPocLog(fmt.Sprintf("Found vuln yonyou BshServlet|%s\n", u+backurl))
				vuln = true
			}
		}
	}
	return vuln
}
