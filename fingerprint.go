package locksmith

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	ua "github.com/mileusna/useragent"
)

type Fingerprint struct {
	IPAddress       string
	UserAgent       string
	DeviceType      string
	Browser         string
	BrowserVersion  string
	OS              string
	OSVersion       string
	LocationCountry string
	LocationRegion  string
	LocationCity    string
}

type geoIPResponse struct {
	CountryCode string `json:"countryCode"`
	RegionName  string `json:"regionName"`
	City        string `json:"city"`
	Status      string `json:"status"`
}

func Parse(r *http.Request) Fingerprint {
	ip := extractIP(r)
	parsed := ua.Parse(r.UserAgent())

	deviceType := "desktop"
	if parsed.Mobile {
		deviceType = "mobile"
	} else if parsed.Tablet {
		deviceType = "tablet"
	} else if parsed.Bot {
		deviceType = "other"
	}

	fp := Fingerprint{
		IPAddress:      ip,
		UserAgent:      r.UserAgent(),
		DeviceType:     deviceType,
		Browser:        parsed.Name,
		BrowserVersion: parsed.Version,
		OS:             parsed.OS,
		OSVersion:      parsed.OSVersion,
	}

	if ip != "" && !isPrivateIP(ip) {
		geo := resolveGeoIP(ip)
		fp.LocationCountry = geo.CountryCode
		fp.LocationRegion = geo.RegionName
		fp.LocationCity = geo.City
	}

	return fp
}

func ExtractIP(r *http.Request) string {
	return extractIP(r)
}

func extractIP(r *http.Request) string {
	// Check X-Forwarded-For (proxy/nginx)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		if ip := strings.TrimSpace(parts[0]); ip != "" {
			return ip
		}
	}
	// Check X-Real-IP
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}
	// Fall back to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	private := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fc00::/7",
	}
	for _, cidr := range private {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func resolveGeoIP(ip string) geoIPResponse {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://ip-api.com/json/" + ip + "?fields=status,countryCode,regionName,city")
	if err != nil {
		return geoIPResponse{}
	}
	defer resp.Body.Close()

	var geo geoIPResponse
	if err := json.NewDecoder(resp.Body).Decode(&geo); err != nil {
		return geoIPResponse{}
	}
	if geo.Status != "success" {
		return geoIPResponse{}
	}
	return geo
}
