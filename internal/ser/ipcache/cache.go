package ipcache

import (
	"net"
	"strings"
	"sync"
	"time"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
)

type blacklistCIDR struct {
	network *net.IPNet
	entry   model.IPBlacklist
}
type whitelistCIDR struct {
	network *net.IPNet
	entry   model.IPWhitelist
}
type snapshot struct {
	black      map[string]model.IPBlacklist
	white      map[string]model.IPWhitelist
	blackCIDRs []blacklistCIDR
	whiteCIDRs []whitelistCIDR
	expires    time.Time
}

var mu sync.RWMutex
var current *snapshot

func Invalidate() { mu.Lock(); current = nil; mu.Unlock() }
func load() (*snapshot, error) {
	mu.RLock()
	s := current
	mu.RUnlock()
	if s != nil && time.Now().Before(s.expires) {
		return s, nil
	}
	mu.Lock()
	defer mu.Unlock()
	if current != nil && time.Now().Before(current.expires) {
		return current, nil
	}
	var black []model.IPBlacklist
	var white []model.IPWhitelist
	if err := dao.GetDB().Where("status = 1").Find(&black).Error; err != nil {
		return nil, err
	}
	if err := dao.GetDB().Where("status = 1").Find(&white).Error; err != nil {
		return nil, err
	}
	s = &snapshot{black: map[string]model.IPBlacklist{}, white: map[string]model.IPWhitelist{}, expires: time.Now().Add(5 * time.Second)}
	for _, entry := range black {
		if strings.Contains(entry.IP, "/") {
			_, network, err := net.ParseCIDR(entry.IP)
			if err == nil {
				s.blackCIDRs = append(s.blackCIDRs, blacklistCIDR{network, entry})
			}
		} else {
			s.black[entry.IP] = entry
		}
	}
	for _, entry := range white {
		if strings.Contains(entry.IP, "/") {
			_, network, err := net.ParseCIDR(entry.IP)
			if err == nil {
				s.whiteCIDRs = append(s.whiteCIDRs, whitelistCIDR{network, entry})
			}
		} else {
			s.white[entry.IP] = entry
		}
	}
	current = s
	return s, nil
}
func IsBlocked(ip string) (bool, *model.IPBlacklist, error) {
	s, err := load()
	if err != nil {
		return false, nil, err
	}
	if entry, ok := s.black[ip]; ok && !entry.IsExpired() {
		return true, &entry, nil
	}
	parsed := net.ParseIP(ip)
	for _, cidr := range s.blackCIDRs {
		if cidr.network.Contains(parsed) && !cidr.entry.IsExpired() {
			entry := cidr.entry
			return true, &entry, nil
		}
	}
	return false, nil, nil
}
func IsWhitelisted(ip string) (bool, error) {
	s, err := load()
	if err != nil {
		return false, err
	}
	if entry, ok := s.white[ip]; ok && !entry.IsExpired() {
		return true, nil
	}
	parsed := net.ParseIP(ip)
	for _, cidr := range s.whiteCIDRs {
		if cidr.network.Contains(parsed) && !cidr.entry.IsExpired() {
			return true, nil
		}
	}
	return false, nil
}
