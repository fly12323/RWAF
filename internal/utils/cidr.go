package utils

import (
	"net"
	"strings"
)

// MatchCIDR 检查IP是否在CIDR范围内
func MatchCIDR(ip, cidr string) bool {
	// 如果不是CIDR格式，直接比较
	if !strings.Contains(cidr, "/") {
		return ip == cidr
	}

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	return ipNet.Contains(parsedIP)
}

// ParseIP 解析IP地址
func ParseIP(ip string) net.IP {
	return net.ParseIP(ip)
}

// IsIPv4 检查是否是IPv4
func IsIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.To4() != nil
}

// IsIPv6 检查是否是IPv6
func IsIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.To4() == nil
}
