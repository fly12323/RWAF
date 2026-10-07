package dao

import (
	"errors"
	"gorm.io/gorm"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/model"
)

// Preserve legacy *global* CC/auto-ban values, without choosing any site's overrides.
// Old tables/columns remain as rollback data; runtime no longer reads them.
func initializeProtection(tx *gorm.DB) error {
	var count int64
	if err := tx.Model(&model.ProtectionConfig{}).Where("id = 1").Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	cfg := config.GetConfig().WAF
	policy := model.DefaultProtectionConfig(cfg.DefaultMode, cfg.DefaultScoreThreshold)
	if tx.Migrator().HasTable("cc_protection_config") {
		query := tx.Table("cc_protection_config")
		if tx.Migrator().HasColumn("cc_protection_config", "site_id") {
			query = query.Where("site_id IS NULL")
		}
		var cc model.CCProtectionConfig
		if err := query.Order("id DESC").Take(&cc).Error; err == nil {
			policy.CCProtectionEnabled = cc.Enabled
			policy.CCRequestsPerMinute = cc.RequestsPerMinute
			policy.CCAction = cc.Action
			policy.CCDelayMs = cc.DelayMs
			policy.CCURILimits = cc.URILimits
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
	}
	if tx.Migrator().HasTable("auto_block_config") {
		query := tx.Table("auto_block_config")
		if tx.Migrator().HasColumn("auto_block_config", "site_id") {
			query = query.Where("site_id IS NULL")
		}
		var auto model.AutoBlockConfig
		if err := query.Order("id DESC").Take(&auto).Error; err == nil {
			policy.AutoBlockEnabled = auto.Enabled
			policy.AutoBlockThreshold = auto.Threshold
			policy.AutoBlockDuration = auto.Duration
			policy.AutoBlockHours = auto.BlockHours
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
	}
	if policy.CCURILimits == "" {
		policy.CCURILimits = "[]"
	}
	return tx.Create(&policy).Error
}
