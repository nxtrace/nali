package leomoeapi

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
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

func Find(query string, params ...string) (result fmt.Stringer, err error) {

	//res, err := ipgeo.LeoIP(query)
	res, err := FetchIPInfo(query)
	if err != nil {
		return nil, err
	}
	result = Result{
		Data: strings.Join(func() []string {
			dataSlice := make([]string, 0, 7)
			fields := []string{
				res.Asnumber,
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
