package leomoeapi

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"net"
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

func FetchIPInfo(ip string) (*IPGeoData, error) {
	c, _, err := websocket.DefaultDialer.Dial("wss://api.leo.moe/v2/ipGeoWs", nil)
	if err != nil {
		return nil, fmt.Errorf("websocket dial: %w", err)
	}
	defer c.Close()

	if err := c.WriteMessage(websocket.TextMessage, []byte(ip)); err != nil {
		return nil, fmt.Errorf("write message: %w", err)
	}

	_, message, err := c.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}

	var data IPGeoData
	if err := json.Unmarshal(message, &data); err != nil {
		return nil, fmt.Errorf("json unmarshal: %w", err)
	}

	return &data, nil
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

func Find(query string, params ...string) (result fmt.Stringer, err error) {
	if net.ParseIP(query) == nil {
		return Result{""}, nil // 如果 query 不是一个有效的 IP 地址，返回空字符串
	}
	if isPrivateOrReserved(net.ParseIP(query)) {
		return Result{""}, nil // 如果 query 是一个私有或保留地址，返回空字符串
	}
	res, err := FetchIPInfo(query)
	if err != nil {
		return nil, err
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

	return result, nil
}
