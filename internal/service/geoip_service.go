package service

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"sync"
	"time"
)

type GeoIPInfo struct {
	Country string   `json:"country"`
	Region  string   `json:"region"`
	City    string   `json:"city"`
	Lat     *float64 `json:"lat"`
	Lon     *float64 `json:"lon"`
}

type geoIPCacheItem struct {
	info      GeoIPInfo
	expiresAt time.Time
}

type GeoIPService struct {
	client *http.Client
	mu     sync.RWMutex
	cache  map[string]geoIPCacheItem
	ttl    time.Duration
}

func NewGeoIPService() *GeoIPService {
	return &GeoIPService{
		client: &http.Client{
			Timeout: 4 * time.Second,
		},
		cache: make(map[string]geoIPCacheItem),
		ttl:   24 * time.Hour,
	}
}

type ipAPIResp struct {
	Status     string  `json:"status"`
	Message    string  `json:"message"`
	Query      string  `json:"query"`
	Country    string  `json:"country"`
	RegionName string  `json:"regionName"`
	City       string  `json:"city"`
	Lat        float64 `json:"lat"`
	Lon        float64 `json:"lon"`
}

func (s *GeoIPService) Lookup(ctx context.Context, ip string) (GeoIPInfo, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return GeoIPInfo{}, nil
	}
	if parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
		return GeoIPInfo{}, nil
	}

	now := time.Now()
	s.mu.RLock()
	if item, ok := s.cache[ip]; ok && now.Before(item.expiresAt) {
		s.mu.RUnlock()
		return item.info, nil
	}
	s.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://ip-api.com/json/"+ip+"?fields=status,message,country,regionName,city,lat,lon,query", nil)
	if err != nil {
		return GeoIPInfo{}, err
	}
	res, err := s.client.Do(req)
	if err != nil {
		return GeoIPInfo{}, err
	}
	defer res.Body.Close()

	var out ipAPIResp
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		return GeoIPInfo{}, err
	}
	if out.Status != "success" {
		s.mu.Lock()
		s.cache[ip] = geoIPCacheItem{info: GeoIPInfo{}, expiresAt: now.Add(30 * time.Minute)}
		s.mu.Unlock()
		return GeoIPInfo{}, nil
	}

	lat := out.Lat
	lon := out.Lon
	info := GeoIPInfo{
		Country: out.Country,
		Region:  out.RegionName,
		City:    out.City,
		Lat:     &lat,
		Lon:     &lon,
	}

	s.mu.Lock()
	s.cache[ip] = geoIPCacheItem{info: info, expiresAt: now.Add(s.ttl)}
	s.mu.Unlock()

	return info, nil
}
