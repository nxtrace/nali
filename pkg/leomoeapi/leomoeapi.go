package leomoeapi

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/xgadget-lab/nexttrace/util"
	"github.com/zu1k/nali/pow"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type IPGeoData struct {
	IP        string              `json:"ip"`
	Asnumber  string              `json:"asnumber"`
	Country   string              `json:"country"`
	CountryEn string              `json:"country_en"`
	Prov      string              `json:"prov"`
	ProvEn    string              `json:"prov_en"`
	City      string              `json:"city"`
	CityEn    string              `json:"city_en"`
	District  string              `json:"district"`
	Owner     string              `json:"owner"`
	Isp       string              `json:"isp"`
	Domain    string              `json:"domain"`
	Whois     string              `json:"whois"`
	Lat       float64             `json:"lat"`
	Lng       float64             `json:"lng"`
	Prefix    string              `json:"prefix"`
	Router    map[string][]string `json:"router"`
	Source    string              `json:"source"`
}

var conn *websocket.Conn

func FetchIPInfo(ip string, token string) (*IPGeoData, string, error) {
	var host, port, fastIp string
	host, port = util.GetHostAndPort()
	// 如果 host 是一个 IP 使用默认域名
	if valid := net.ParseIP(host); valid != nil {
		host = "api.leo.moe"
	} else {
		// 默认配置完成，开始寻找最优 IP
		fastIp = util.GetFastIP(host, port, false)
	}
	//host, port, fastIp = "103.120.18.35", "api.leo.moe", "443"
	envToken := util.EnvToken
	jwtToken := token
	ua := []string{pow.UserAgent}
	if envToken != "" {
		ua = []string{"Privileged Client"}
	}

	if token == "" {
		// 如果没有传入 token，尝试从环境变量中获取
		jwtToken = envToken
		err := error(nil)
		if envToken == "" {
			// 如果环境变量中没有 token，尝试从 pow 获取
			jwtToken, err = pow.GetToken(fastIp, host, port)
			if err != nil {
				log.Println(err)
				os.Exit(1)
			}

		}
	}

	requestHeader := http.Header{
		"Host":          []string{host},
		"User-Agent":    ua,
		"Authorization": []string{"Bearer " + jwtToken},
	}
	dialer := websocket.DefaultDialer
	dialer.TLSClientConfig = &tls.Config{
		ServerName: host,
	}
	u := url.URL{Scheme: "wss", Host: fastIp + ":" + port, Path: "/v3/ipGeoWs"}

	var c *websocket.Conn
	var err error

	if conn == nil {
		c, _, err = websocket.DefaultDialer.Dial(u.String(), requestHeader)
		if err != nil {
			return nil, "", fmt.Errorf("websocket dial: %w", err)
		}
		c.SetCloseHandler(func(code int, text string) error {
			conn = nil // 将全局的 conn 设为 nil
			return nil
		})
		// ws留给下次复用
		conn = c
	} else {
		c = conn
	}

	//defer func(c *websocket.Conn) {
	//	err := c.Close()
	//	if err != nil {
	//		log.Println(err)
	//	}
	//}(c)
	// TODO: 现在是一直不关闭，以后想办法在程序退出时关闭
	// 在这种情况下，你可以考虑使用Go的 os/signal 包来监听操作系统发出的终止信号。当程序收到这样的信号时，
	// 比如 SIGINT（即 Ctrl+C）或 SIGTERM，你可以优雅地关闭你的 WebSocket 连接。

	if err := c.WriteMessage(websocket.TextMessage, []byte(ip)); err != nil {
		return nil, "", fmt.Errorf("write message: %w", err)
	}

	_, message, err := c.ReadMessage()
	if err != nil {
		return nil, "", fmt.Errorf("read message: %w", err)
	}

	var data IPGeoData
	if err := json.Unmarshal(message, &data); err != nil {
		return nil, "", fmt.Errorf("json unmarshal: %w", err)
	}

	return &data, jwtToken, nil
}

type Result struct {
	Data string
}

func (r Result) String() string {
	return r.Data
}

func isPrivateOrReserved(ip net.IP) bool {
	privateIPv4 := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10",   // Shared Address Space (also known as Carrier-Grade NAT, or CGN)
		"198.18.0.0/15",   // Network Interconnect Device Benchmark Testing
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"240.0.0.0/4",     // Reserved for future use
	}

	privateIPv6 := []string{
		"FC00::/7",  // Unique Local Address
		"FE80::/10", // Link-local address
	}

	reservedIPv4 := []string{
		"0.0.0.0/8",
		"6.0.0.0/7",
		"11.0.0.0/8",
		"21.0.0.0/8",
		"22.0.0.0/8",
		"26.0.0.0/8",
		"28.0.0.0/8",
		"29.0.0.0/8",
		"30.0.0.0/8",
		"33.0.0.0/8",
		"55.0.0.0/8",
		"214.0.0.0/8",
		"215.0.0.0/8",
	}

	reservedIPv6 := []string{
		"::1/128",  // loopback address
		"::/128",   // unspecified address
		"FF00::/8", // multicast address
	}

	for _, cidr := range append(privateIPv4, reservedIPv4...) {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}

	if ip.To4() == nil {
		for _, cidr := range append(privateIPv6, reservedIPv6...) {
			_, network, _ := net.ParseCIDR(cidr)
			if network.Contains(ip) {
				return true
			}
		}
	}

	return false
}

func Find(query string, token string) (result fmt.Stringer, retToken string, err error) {
	if net.ParseIP(query) == nil {
		return Result{""}, token, nil // 如果 query 不是一个有效的 IP 地址，返回空字符串
	}
	if isPrivateOrReserved(net.ParseIP(query)) {
		return Result{""}, token, nil // 如果 query 是一个私有或保留地址，返回空字符串
	}
	i := 0
	var res *IPGeoData
	for i = 0; i < 3; i++ {
		res, token, err = FetchIPInfo(query, token)
		if err != nil {
			continue
		}
		break
	}
	if i == 3 {
		return nil, "", err
	}

	result = Result{
		Data: strings.Join(func() []string {
			dataSlice := make([]string, 0, 7)
			fields := []string{
				"AS" + res.Asnumber,
				res.Country,
				res.Prov,
				res.City,
				res.District,
			}
			for _, field := range fields {
				if field != "" {
					dataSlice = append(dataSlice, field)
				}
			}
			if res.Owner != "" {
				dataSlice = append(dataSlice, res.Owner)
			} else {
				dataSlice = append(dataSlice, res.Isp)
			}
			return dataSlice
		}(), ";"),
	}

	return result, token, nil
}
