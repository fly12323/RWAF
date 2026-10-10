package service

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var ErrBuiltinRuleReadOnly = errors.New("内置规则只读，不能修改、删除或单独切换状态；防护策略请在全局防护中配置")
var catalogID = regexp.MustCompile(`(?:^|[,"\s])id\s*:\s*['"]?(\d+)`)
var catalogMessage = regexp.MustCompile(`(?:^|,)\s*msg:'((?:\\.|[^'\\])*)'`)
var catalogSeverity = regexp.MustCompile(`(?:^|,)\s*severity:['"]?([A-Za-z0-9]+)`)
var catalogChain = regexp.MustCompile(`(?:^|,)\s*chain(?:[,"\s]|$)`)

func ruleCategory(file string) string {
	name := strings.ToUpper(filepath.Base(file))
	if strings.Contains(name, "934-") {
		return "Generic Attack"
	}
	if strings.Contains(name, "911-") {
		return "Protocol"
	}
	if strings.Contains(name, "905-") || strings.Contains(name, "999-") {
		return "Exclusion"
	}
	for _, pair := range [][2]string{{"942-", "SQL Injection"}, {"941-", "XSS"}, {"930-", "LFI"}, {"931-", "RFI"}, {"932-", "RCE"}, {"933-", "PHP Injection"}, {"934-", "Node.js Injection"}, {"944-", "Java Attack"}, {"943-", "Session Fixation"}, {"913-", "Scanner"}, {"920-", "Protocol"}, {"921-", "Protocol"}, {"922-", "Protocol"}, {"901-", "Initialization"}, {"949-", "Blocking Evaluation"}, {"959-", "Blocking Evaluation"}, {"980-", "Correlation"}, {"900-", "Exclusion"}, {"950-", "Data Leakage"}, {"951-", "Data Leakage"}, {"952-", "Data Leakage"}, {"953-", "Data Leakage"}, {"954-", "Data Leakage"}, {"955-", "Data Leakage"}, {"956-", "Data Leakage"}} {
		if strings.Contains(name, pair[0]) {
			return pair[1]
		}
	}
	if strings.Contains(name, "SETUP") {
		return "Initialization"
	}
	return "Other"
}

// ParseBuiltinRules retains full continued directives and chained child rules.
// This is a read-only catalogue; the Coraza engine remains the authority for execution.
func ParseBuiltinRules(file string, content string) ([]model.Rule, error) {
	scanner := bufio.NewScanner(strings.NewReader(content))
	scanner.Buffer(make([]byte, 4096), 4*1024*1024)
	var directives []string
	var current strings.Builder
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if current.Len() > 0 {
			current.WriteByte('\n')
		}
		current.WriteString(strings.TrimRight(scanner.Text(), " \t\r"))
		if !strings.HasSuffix(line, `\`) {
			directives = append(directives, current.String())
			current.Reset()
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if current.Len() > 0 {
		return nil, fmt.Errorf("未完成的规则指令: %s", file)
	}
	rules := []model.Rule{}
	chain := false
	for _, raw := range directives {
		flat := strings.ReplaceAll(raw, "\\\n", "")
		if !strings.HasPrefix(strings.TrimSpace(flat), "SecRule ") && !strings.HasPrefix(strings.TrimSpace(flat), "SecAction ") {
			chain = false
			continue
		}
		id := catalogID.FindStringSubmatch(flat)
		if len(id) == 0 {
			if chain && len(rules) > 0 {
				rules[len(rules)-1].RuleContent += "\n" + raw
			}
			chain = catalogChain.MatchString(flat)
			continue
		}
		severity := "NOTICE"
		if match := catalogSeverity.FindStringSubmatch(flat); len(match) > 0 {
			severity = strings.ToUpper(match[1])
		}
		score := map[string]int{"CRITICAL": 10, "ERROR": 8, "WARNING": 5, "NOTICE": 2, "INFO": 1}[severity]
		description := "规则 " + id[1]
		if match := catalogMessage.FindStringSubmatch(flat); len(match) > 0 {
			description = strings.ReplaceAll(match[1], `\'`, `'`)
		}
		text := []rune(description)
		if len(text) > 500 {
			description = string(text[:500])
		}
		rules = append(rules, model.Rule{RuleID: id[1], RuleFile: filepath.ToSlash(file), RuleContent: raw, Category: ruleCategory(file), Severity: severity, Score: score, Description: description, Enabled: true, IsCustom: false})
		chain = catalogChain.MatchString(flat)
	}
	return rules, nil
}

func (s *RuleService) SyncBuiltinCatalog() error {
	cfg := config.GetConfig().WAF
	files, err := filepath.Glob(filepath.Join(cfg.CrsDir, "rules", "*.conf"))
	if err != nil {
		return err
	}
	setup := filepath.Join(cfg.CrsDir, "crs-setup.conf")
	if _, err := os.Stat(setup); err == nil {
		files = append(files, setup)
	}
	extra, err := filepath.Glob(filepath.Join(cfg.CustomRulesDir, "*.conf"))
	if err != nil {
		return err
	}
	for _, file := range extra {
		if filepath.Base(file) != "custom-rules.conf" {
			files = append(files, file)
		}
	}
	all := []model.Rule{}
	ids := map[string]bool{}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		rules, err := ParseBuiltinRules(file, string(data))
		if err != nil {
			return err
		}
		for _, rule := range rules {
			if ids[rule.RuleID] {
				return fmt.Errorf("目录中的规则 ID 重复: %s", rule.RuleID)
			}
			ids[rule.RuleID] = true
			all = append(all, rule)
		}
	}
	if len(all) == 0 {
		return nil
	}
	return dao.GetDB().Transaction(func(tx *gorm.DB) error {
		return tx.Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "rule_id"}}, DoUpdates: clause.AssignmentColumns([]string{"rule_file", "rule_content", "category", "severity", "score", "description", "updated_at"}), Where: clause.Where{Exprs: []clause.Expression{clause.Eq{Column: clause.Column{Table: "rules", Name: "is_custom"}, Value: false}}}}).CreateInBatches(&all, 100).Error
	})
}
