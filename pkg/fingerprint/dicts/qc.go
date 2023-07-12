package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

type Fingerprint struct {
	Cms      string   `json:"cms"`
	Method   string   `json:"method"`
	Location string   `json:"location"`
	Keyword  []string `json:"keyword"`
}

func main() {
	// 假设这里的 jsonFile 是您要加载的 JSON 文件
	jsonFile := "fingerprint.json"

	// 读取 JSON 文件内容
	data, err := ioutil.ReadFile(jsonFile)
	if err != nil {
		fmt.Println(err)
		return
	}

	// 解析 JSON 内容
	var fp map[string][]Fingerprint
	if err := json.Unmarshal(data, &fp); err != nil {
		fmt.Println(err)
		return
	}

	// 去重相同 cms 和 keyword 的内容
	cmsKeywordMap := make(map[string]map[string]bool)
	result := make([]Fingerprint, 0)
	for _, fpList := range fp["fingerprint"] {
		key := fpList.Cms + "-" + fmt.Sprintf("%v", fpList.Keyword)
		if cmsKeywordMap[fpList.Cms] == nil {
			cmsKeywordMap[fpList.Cms] = make(map[string]bool)
		}
		if !cmsKeywordMap[fpList.Cms][key] {
			cmsKeywordMap[fpList.Cms][key] = true
			result = append(result, fpList)
		}
	}

	// 将结果转换为 JSON 格式并输出
	output, err := json.MarshalIndent(map[string][]Fingerprint{"fingerprint": result}, "", "  ")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(output))
	//if err := ioutil.WriteFile("savs.json", output, os.ModePerm); err != nil {
	//	fmt.Println(err)
	//	return
	//}
}
