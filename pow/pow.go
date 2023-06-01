package pow

import (
	"fmt"
	"github.com/tsosunchia/powclient"
	"github.com/zu1k/nali/internal/constant"
	"net/url"
	"os"
	"runtime"
)

const (
	baseURL = "/v3/challenge"
)

var UserAgent = fmt.Sprintf("Nali-NextTrace %s/%s/%s", constant.Version, runtime.GOOS, runtime.GOARCH)

func GetToken(fastIp string, host string, port string) (string, error) {
	getTokenParams := powclient.NewGetTokenParams()
	u := url.URL{Scheme: "https", Host: fastIp + ":" + port, Path: baseURL}
	getTokenParams.BaseUrl = u.String()
	getTokenParams.SNI = host
	getTokenParams.Host = host
	getTokenParams.UserAgent = UserAgent
	var err error
	// 尝试三次RetToken，如果都失败了，异常退出
	for i := 0; i < 3; i++ {
		token, err := powclient.RetToken(getTokenParams)
		//fmt.Println(token, err)
		if err != nil {
			continue
		}
		return token, nil
	}
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("RetToken failed 3 times, exit")
	os.Exit(1)
	return "", nil
}
