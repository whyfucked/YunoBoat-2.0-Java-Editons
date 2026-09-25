package main

// geo.go — live IP-to-country resolution for the client registry.
//
// countryCode() in main.go first asks the geolocation API (populated on a
// permanent in-memory cache, so a reconnecting bot never re-queries and the
// free-tier rate limits are never hit). On timeout / API failure it falls
// back to the tiny offline table below, so the registry never stalls.
//
// Only the Go standard library is used, so the C2 still cross-compiles with
// CGO_ENABLED=0 and no external lookup libs.

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	geoMu    sync.Mutex
	geoCache = map[string]string{} // ip -> lowercase 2-letter country code

	// Geo resolvers. ipwho.is is primary (https, keyless); ip-api.com is the
	// fallback. A 4s hard deadline keeps the handshake path from stalling.
	geoClient = &http.Client{Timeout: 4 * time.Second}
	geoProbes = []string{
		"https://ipwho.is/%s",
		"http://ip-api.com/json/%s?fields=countryCode,status",
		"https://ipapi.co/%s/country/",
	}
)

// apiCountryCode resolves one public IP against the geo API and caches it.
// Returns "" when the IP is local/private or every provider timed out, so the
// caller can drop to the offline table.
func apiCountryCode(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" || ip == "::1" || strings.HasPrefix(ip, "127.") {
		return ""
	}
	if strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "172.") || strings.HasPrefix(ip, "169.254.") {
		return ""
	}

	geoMu.Lock()
	if c, ok := geoCache[ip]; ok {
		geoMu.Unlock()
		return c
	}
	geoMu.Unlock()

	var c string
	for _, tmpl := range geoProbes {
		u := strings.Replace(tmpl, "%s", ip, 1)
		c = probeCC(u)
		if c != "" {
			geoMu.Lock()
			geoCache[ip] = c
			geoMu.Unlock()
			return c
		}
	}
	return ""
}

func is172Private(ip string) bool {
	// 172.16.0.0/12 — use 16,31.
	return strings.HasPrefix(ip, "172.16.") || strings.HasPrefix(ip, "172.17.") ||
		strings.HasPrefix(ip, "172.18.") || strings.HasPrefix(ip, "172.19.") ||
		strings.HasPrefix(ip, "172.2") || strings.HasPrefix(ip, "172.3")
}

func probeCC(url string) string {
	resp, err := geoClient.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return ""
	}
	// ipwho.is: {"country_code":"RU"} / ip-api: {"status":"success","countryCode":"RU"}
	var m map[string]interface{}
	if json.Unmarshal(body, &m) == nil {
		if s, ok := m["country_code"].(string); ok {
			return normCC(s)
		}
		if s, ok := m["countryCode"].(string); ok {
			if st, _ := m["status"].(string); st != "" && st != "success" {
				return ""
			}
			return normCC(s)
		}
		if s, ok := m["country"].(string); ok {
			return normCC(s)
		}
	}
	// ipapi.co returns a bare "RU".
	plain := strings.TrimSpace(string(body))
	if len(plain) == 2 {
		return normCC(plain)
	}
	return ""
}

func normCC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if len(s) != 2 {
		return ""
	}
	return s
}

var geoRanges = []uint32{
	0x08000000, 0x0BFFFFFF, // 8.0.0.0/5     — US
	0x17000000, 0x1FFFFFFF, // 23-31.x       — US
	0x3E000000, 0x3EFFFFFF, // 62.0.0.0/8    — EU
	0x41000000, 0x43FFFFFF, // 65-67.x       — NA
	0x44000000, 0x4FFFFFFF, // 68-79.x       — NA/EU
	0x50000000, 0x5FFFFFFF, // 80-95.x       — EU
	0x62000000, 0x63FFFFFF, // 98-99.x       — NA
	0x64000000, 0x6FFFFFFF, // 100-111.x     — mixed
	0x76000000, 0x77FFFFFF, // 118-119.x     — AS
	0x78000000, 0x7FFFFFFF, // 120-127.x     — AS
	0x80000000, 0x8FFFFFFF, // 128-143.x     — EU/NA
	0x90000000, 0x9FFFFFFF, // 144-159.x     — mixed
	0xA0000000, 0xAFFFFFFF, // 160-175.x     — mixed
	0xB0000000, 0xBFFFFFFF, // 176-191.x     — EU/SA
	0xC0000000, 0xC7FFFFFF, // 192-199.x     — NA
	0xC8000000, 0xCFFFFFFF, // 200-207.x     — NA/SA
	0xD0000000, 0xD7FFFFFF, // 208-215.x     — NA
	0xD8000000, 0xDFFFFFFF, // 216-223.x     — NA
}

// geoCC codes cycled over the range pairs above (2-letter, lowercase).
var geoCC = []string{
	"us", "us", "eu", "us", "us", "eu", "us", "as",
	"as", "as", "eu", "as", "ru", "sa", "oc", "us",
}
