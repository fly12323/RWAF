package proxy

import (
	"sync"
	"sync/atomic"
)

// Target 后端服务器目标
type Target struct {
	Host   string `json:"host"`   // 主机地址
	Port   int    `json:"port"`   // 端口
	Weight int    `json:"weight"` // 权重
}

// Balancer 负载均衡器接口
type Balancer interface {
	Next() *Target
	AddTarget(target *Target)
	RemoveTarget(target *Target)
	GetTargets() []*Target
}

// RoundRobinBalancer 轮询负载均衡器
type RoundRobinBalancer struct {
	targets []*Target
	current uint64
	mu      sync.RWMutex
}

// NewRoundRobinBalancer 创建轮询负载均衡器
func NewRoundRobinBalancer() *RoundRobinBalancer {
	return &RoundRobinBalancer{
		targets: make([]*Target, 0),
	}
}

// AddTarget 添加后端服务器
func (b *RoundRobinBalancer) AddTarget(target *Target) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.targets = append(b.targets, target)
}

// RemoveTarget 移除后端服务器
func (b *RoundRobinBalancer) RemoveTarget(target *Target) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, t := range b.targets {
		if t.Host == target.Host && t.Port == target.Port {
			b.targets = append(b.targets[:i], b.targets[i+1:]...)
			break
		}
	}
}

// Next 获取下一个目标服务器
func (b *RoundRobinBalancer) Next() *Target {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if len(b.targets) == 0 {
		return nil
	}

	// 原子操作实现轮询
	idx := atomic.AddUint64(&b.current, 1) - 1
	return b.targets[idx%uint64(len(b.targets))]
}

// GetTargets 获取所有目标服务器
func (b *RoundRobinBalancer) GetTargets() []*Target {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.targets
}

// WeightedRoundRobinBalancer 加权轮询负载均衡器
type WeightedRoundRobinBalancer struct {
	targets []*Target
	weights []int
	current int
	mu      sync.RWMutex
}

// NewWeightedRoundRobinBalancer 创建加权轮询负载均衡器
func NewWeightedRoundRobinBalancer() *WeightedRoundRobinBalancer {
	return &WeightedRoundRobinBalancer{
		targets: make([]*Target, 0),
		weights: make([]int, 0),
	}
}

// AddTarget 添加后端服务器
func (b *WeightedRoundRobinBalancer) AddTarget(target *Target) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.targets = append(b.targets, target)
	b.weights = append(b.weights, target.Weight)
}

// RemoveTarget 移除后端服务器
func (b *WeightedRoundRobinBalancer) RemoveTarget(target *Target) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, t := range b.targets {
		if t.Host == target.Host && t.Port == target.Port {
			b.targets = append(b.targets[:i], b.targets[i+1:]...)
			b.weights = append(b.weights[:i], b.weights[i+1:]...)
			break
		}
	}
}

// Next 获取下一个目标服务器（加权轮询）
func (b *WeightedRoundRobinBalancer) Next() *Target {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.targets) == 0 {
		return nil
	}

	// 简单的加权轮询实现
	totalWeight := 0
	for _, w := range b.weights {
		totalWeight += w
	}

	if totalWeight == 0 {
		return b.targets[0]
	}

	// 计算当前应该选择的目标
	b.current = (b.current + 1) % totalWeight

	weightSum := 0
	for i, w := range b.weights {
		weightSum += w
		if b.current < weightSum {
			return b.targets[i]
		}
	}

	return b.targets[0]
}

// GetTargets 获取所有目标服务器
func (b *WeightedRoundRobinBalancer) GetTargets() []*Target {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.targets
}

// NewBalancer 根据策略创建负载均衡器
func NewBalancer(strategy string) Balancer {
	switch strategy {
	case "round_robin":
		return NewRoundRobinBalancer()
	case "weighted":
		return NewWeightedRoundRobinBalancer()
	default:
		return NewRoundRobinBalancer()
	}
}
