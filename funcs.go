
// ================= 地图与高级分析接口 =================

func getMapData(c *gin.Context) {
	peers, _, _, err := collectPeersData()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type PeerGeo struct {
		PublicKey string  `json:"public_key"`
		Alias     string  `json:"alias"`
		Endpoint  string  `json:"endpoint"`
		IsOnline  bool    `json:"is_online"`
		Lat       float64 `json:"lat"`
		Lon       float64 `json:"lon"`
		City      string  `json:"city"`
		Country   string  `json:"country_code"`
	}

	var data []PeerGeo

	for _, p := range peers {
		if p.Endpoint == "" || p.Endpoint == "未连接" {
			continue
		}

		host, _, err := net.SplitHostPort(p.Endpoint)
		if err != nil {
			host = p.Endpoint // fallback
		}
		
		// Remove brackets if IPv6
		host = strings.Trim(host, "[]")

		ip := net.ParseIP(host)
		if ip == nil {
			continue
		}

		var lat, lon float64
		var city, country string

		if geoCity != nil {
			if record, err := geoCity.City(ip); err == nil {
				lat = record.Location.Latitude
				lon = record.Location.Longitude
				country = record.Country.IsoCode
				if name, ok := record.City.Names["zh-CN"]; ok {
					city = name
				} else {
					city = record.City.Names["en"]
				}
			}
		}

		if lat != 0 || lon != 0 {
			data = append(data, PeerGeo{
				PublicKey: p.PublicKey,
				Alias:     p.Alias,
				Endpoint:  p.Endpoint,
				IsOnline:  p.IsOnline,
				Lat:       lat,
				Lon:       lon,
				City:      city,
				Country:   country,
			})
		}
	}

	c.JSON(http.StatusOK, data)
}

func getAdvancedAnalysis(c *gin.Context) {
	report, err := analysisEngine.GetAdvancedReport()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, report)
}
