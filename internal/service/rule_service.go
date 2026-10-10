package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"

	"gorm.io/gorm"
)

// RuleService 规则服务
type RuleService struct {
	customRulesDir string
}

// NewRuleService 创建规则服务实例
func NewRuleService() *RuleService {
	return &RuleService{
		customRulesDir: "./configs/rules/custom",
	}
}

// SetCustomRulesDir 设置自定义规则目录
func (s *RuleService) SetCustomRulesDir(dir string) {
	s.customRulesDir = dir
}

// GetRuleList 获取规则列表
// page: 页码
// pageSize: 每页数量
// category: 规则分类筛选
// severity: 严重级别筛选
// keyword: 关键词搜索
func (s *RuleService) GetRuleList(page, pageSize int, category, severity, keyword string, profileFilters ...string) ([]model.Rule, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 10
	}
	var rules []model.Rule
	var total int64

	db := dao.GetDB().Model(&model.Rule{})

	// 添加筛选条件
	if category != "" {
		db = db.Where("category = ?", category)
	}
	if severity != "" {
		db = db.Where("severity = ?", severity)
	}
	if keyword != "" {
		db = db.Where("rule_id LIKE ? OR description LIKE ?", "%"+keyword+"%", "%"+keyword+"%")
	}

	// Classify before pagination so filtered totals cover the entire catalogue.
	if len(profileFilters) > 0 && (profileFilters[0] != "" || (len(profileFilters) > 1 && profileFilters[1] != "")) {
		if err := db.Order("rule_id ASC").Find(&rules).Error; err != nil {
			return nil, 0, err
		}
		filtered := make([]model.Rule, 0, len(rules))
		for _, r := range rules {
			r.Profile = model.DescribeRule(r)
			if profileFilters[0] != "" && r.Profile.FalsePositiveRisk != profileFilters[0] {
				continue
			}
			if len(profileFilters) > 1 && profileFilters[1] != "" && r.Profile.Scope != profileFilters[1] {
				continue
			}
			filtered = append(filtered, r)
		}
		total = int64(len(filtered))
		if page > len(filtered)/pageSize+1 {
			return []model.Rule{}, total, nil
		}
		start := (page - 1) * pageSize
		if start >= len(filtered) {
			return []model.Rule{}, total, nil
		}
		end := start + pageSize
		if end > len(filtered) {
			end = len(filtered)
		}
		return filtered[start:end], total, nil
	}
	// 统计总数
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// 分页查询
	offset := (page - 1) * pageSize
	if err := db.Offset(offset).Limit(pageSize).Order("rule_id ASC").Find(&rules).Error; err != nil {
		return nil, 0, err
	}

	for i := range rules {
		rules[i].Profile = model.DescribeRule(rules[i])
	}
	return rules, total, nil
}

// GetRuleByID 根据ID获取规则详情
func (s *RuleService) GetRuleByID(id uint) (*model.Rule, error) {
	var rule model.Rule
	if err := dao.GetDB().First(&rule, id).Error; err != nil {
		return nil, err
	}
	rule.Profile = model.DescribeRule(rule)
	return &rule, nil
}

// GetRuleByRuleID 根据规则ID获取规则
func (s *RuleService) GetRuleByRuleID(ruleID string) (*model.Rule, error) {
	var rule model.Rule
	if err := dao.GetDB().Where("rule_id = ?", ruleID).First(&rule).Error; err != nil {
		return nil, err
	}
	rule.Profile = model.DescribeRule(rule)
	return &rule, nil
}

// CreateRuleRequest 创建规则请求
type CreateRuleRequest struct {
	RuleID      string `json:"rule_id" binding:"required"`
	RuleFile    string `json:"rule_file"`
	RuleContent string `json:"rule_content"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Score       int    `json:"score"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
}

// CreateRule 创建自定义规则
func (s *RuleService) CreateRule(req *CreateRuleRequest) (*model.Rule, error) {
	// 检查规则ID是否已存在
	var count int64
	dao.GetDB().Model(&model.Rule{}).Where("rule_id = ?", req.RuleID).Count(&count)
	if count > 0 {
		return nil, gorm.ErrDuplicatedKey
	}

	// 设置默认值
	if req.Severity == "" {
		req.Severity = "WARNING"
	}
	if req.Score == 0 {
		req.Score = 5
	}

	rule := &model.Rule{
		RuleID:      req.RuleID,
		RuleFile:    req.RuleFile,
		RuleContent: req.RuleContent,
		Category:    req.Category,
		Severity:    req.Severity,
		Score:       req.Score,
		Description: req.Description,
		Enabled:     req.Enabled,
		IsCustom:    true,
	}

	if err := dao.GetDB().Create(rule).Error; err != nil {
		return nil, err
	}

	// 同步到文件
	s.SyncRulesToFile()

	return rule, nil
}

// UpdateRuleRequest 更新规则请求
type UpdateRuleRequest struct {
	RuleFile    string `json:"rule_file"`
	RuleContent string `json:"rule_content"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Score       int    `json:"score"`
	Description string `json:"description"`
	Enabled     *bool  `json:"enabled"`
}

// UpdateRule 更新规则
func (s *RuleService) UpdateRule(id uint, req *UpdateRuleRequest) (*model.Rule, error) {
	rule, err := s.GetRuleByID(id)
	if err != nil {
		return nil, err
	}
	if !rule.IsCustom {
		return nil, ErrBuiltinRuleReadOnly
	}

	updates := make(map[string]interface{})

	if req.RuleFile != "" {
		updates["rule_file"] = req.RuleFile
	}
	if req.RuleContent != "" {
		updates["rule_content"] = req.RuleContent
	}
	if req.Category != "" {
		updates["category"] = req.Category
	}
	if req.Severity != "" {
		updates["severity"] = req.Severity
	}
	if req.Score > 0 {
		updates["score"] = req.Score
	}
	if req.Description != "" {
		updates["description"] = req.Description
	}
	if req.Enabled != nil {
		updates["enabled"] = *req.Enabled
	}

	if err := dao.GetDB().Model(rule).Updates(updates).Error; err != nil {
		return nil, err
	}

	// 同步到文件
	s.SyncRulesToFile()

	return s.GetRuleByID(id)
}

// DeleteRule 删除规则（只能删除自定义规则）
func (s *RuleService) DeleteRule(id uint) error {
	rule, err := s.GetRuleByID(id)
	if err != nil {
		return err
	}

	// 只能删除自定义规则
	if !rule.IsCustom {
		return ErrBuiltinRuleReadOnly
	}

	if err := dao.GetDB().Delete(&model.Rule{}, id).Error; err != nil {
		return err
	}

	// 同步到文件
	s.SyncRulesToFile()

	return nil
}

// ToggleRuleStatus 切换规则启用状态
func (s *RuleService) ToggleRuleStatus(id uint, enabled bool) error {
	rule, err := s.GetRuleByID(id)
	if err != nil {
		return err
	}
	if !rule.IsCustom {
		return ErrBuiltinRuleReadOnly
	}
	if err := dao.GetDB().Model(&model.Rule{}).Where("id = ?", id).Update("enabled", enabled).Error; err != nil {
		return err
	}
	// 同步到文件
	s.SyncRulesToFile()
	return nil
}

// GetRuleCategories 获取所有规则分类
func (s *RuleService) GetRuleCategories() ([]map[string]interface{}, error) {
	var categories []map[string]interface{}
	if err := dao.GetDB().Model(&model.Rule{}).Select("category, count(*) as count").Group("category").Order("category").Find(&categories).Error; err != nil {
		return nil, err
	}
	return categories, nil
}

// GetRuleStatistics 获取规则统计信息
func (s *RuleService) GetRuleStatistics() (map[string]interface{}, error) {
	var total, enabled, custom int64

	dao.GetDB().Model(&model.Rule{}).Count(&total)
	dao.GetDB().Model(&model.Rule{}).Where("enabled = ?", true).Count(&enabled)
	dao.GetDB().Model(&model.Rule{}).Where("is_custom = ?", true).Count(&custom)

	// 按严重级别统计
	var severityStats []struct {
		Severity string
		Count    int64
	}
	dao.GetDB().Model(&model.Rule{}).Select("severity, count(*) as count").Group("severity").Scan(&severityStats)

	// 按分类统计
	var categoryStats []struct {
		Category string
		Count    int64
	}
	dao.GetDB().Model(&model.Rule{}).Select("category, count(*) as count").Group("category").Scan(&categoryStats)

	return map[string]interface{}{
		"total":       total,
		"enabled":     enabled,
		"custom":      custom,
		"by_severity": severityStats,
		"by_category": categoryStats,
	}, nil
}

// SyncRulesToFile 将数据库中的自定义规则同步到 .conf 文件
func (s *RuleService) SyncRulesToFile() error {
	// 获取所有启用的自定义规则
	var rules []model.Rule
	if err := dao.GetDB().Where("is_custom = ? AND enabled = ?", true, true).Find(&rules).Error; err != nil {
		return fmt.Errorf("查询自定义规则失败: %w", err)
	}

	// 确保目录存在
	if err := os.MkdirAll(s.customRulesDir, 0755); err != nil {
		return fmt.Errorf("创建规则目录失败: %w", err)
	}

	// 生成规则文件内容
	var content strings.Builder
	content.WriteString("# Custom Rules - Auto Generated\n")
	content.WriteString("# 请勿手动修改此文件，修改将通过前端界面进行\n\n")

	for _, rule := range rules {
		if rule.RuleContent != "" {
			// 添加规则注释
			if rule.Description != "" {
				content.WriteString(fmt.Sprintf("# %s\n", rule.Description))
			}
			content.WriteString(rule.RuleContent)
			content.WriteString("\n\n")
		}
	}

	// 写入文件
	ruleFile := filepath.Join(s.customRulesDir, "custom-rules.conf")
	if err := os.WriteFile(ruleFile, []byte(content.String()), 0644); err != nil {
		return fmt.Errorf("写入规则文件失败: %w", err)
	}

	fmt.Printf("[规则同步] 已将 %d 条规则同步到 %s\n", len(rules), ruleFile)
	return nil
}

// SyncAllRules 启动时同步所有自定义规则到文件
func (s *RuleService) SyncAllRules() error {
	return s.SyncRulesToFile()
}
