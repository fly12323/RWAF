package dao

import (
	"errors"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/model"
	"github.com/google/uuid"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
	"strings"
	"testing"
)

func TestLegacyGlobalPolicyMigration(t *testing.T) {
	if os.Getenv("WAF_INTEGRATION") != "1" {
		t.Skip("requires disposable PostgreSQL on 15432")
	}
	db, err := gorm.Open(postgres.Open("host=127.0.0.1 port=15432 user=waf_test password=waf-test-only dbname=waf_test sslmode=disable"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, _ := db.DB()
	defer sqlDB.Close()
	config.GlobalConfig = &config.Config{WAF: config.WAFConfig{DefaultMode: "block", DefaultScoreThreshold: 15}}
	rollback := errors.New("rollback test schema")
	err = db.Transaction(func(tx *gorm.DB) error {
		schema := "protection_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
		// Schema name consists exclusively of generated hexadecimal/digit text.
		if err := tx.Exec("CREATE SCHEMA " + schema).Error; err != nil {
			return err
		}
		if err := tx.Exec("SET LOCAL search_path TO " + schema).Error; err != nil {
			return err
		}
		if err := tx.AutoMigrate(&model.ProtectionConfig{}, &model.CCProtectionConfig{}, &model.AutoBlockConfig{}); err != nil {
			return err
		}
		for _, table := range []string{"cc_protection_config", "auto_block_config"} {
			if err := tx.Exec("ALTER TABLE " + table + " ADD COLUMN site_id bigint").Error; err != nil {
				return err
			}
		}
		if err := tx.Exec("INSERT INTO cc_protection_config(id,enabled,requests_per_minute,uri_limits,action,delay_ms,site_id) VALUES (1,false,321,'[]','block',0,NULL),(2,true,999,'[]','block',1,42)").Error; err != nil {
			return err
		}
		if err := tx.Exec("INSERT INTO auto_block_config(id,enabled,threshold,duration,block_hours,site_id) VALUES (1,false,7,45,0,NULL),(2,true,999,999,999,42)").Error; err != nil {
			return err
		}
		if err := initializeProtection(tx); err != nil {
			return err
		}
		var c model.ProtectionConfig
		if err := tx.First(&c, 1).Error; err != nil {
			return err
		}
		if c.CCProtectionEnabled || c.CCRequestsPerMinute != 321 || c.CCDelayMs != 0 || c.AutoBlockEnabled || c.AutoBlockThreshold != 7 || c.AutoBlockDuration != 45 || c.AutoBlockHours != 0 {
			return errors.New("legacy global values were lost or a site override was imported")
		}
		c.ScoreThreshold = 77
		if err := tx.Model(&c).Update("score_threshold", 77).Error; err != nil {
			return err
		}
		// Simulate a persisted policy from before the PL column was introduced.
		if err := tx.Exec("ALTER TABLE global_protection_config DROP COLUMN paranoia_level").Error; err != nil {
			return err
		}
		if err := tx.AutoMigrate(&model.ProtectionConfig{}); err != nil {
			return err
		}
		if err := initializeProtection(tx); err != nil {
			return err
		}
		if err := tx.First(&c, 1).Error; err != nil {
			return err
		}
		if c.ScoreThreshold != 77 || c.ParanoiaLevel != 1 {
			return errors.New("repeated migration overwrote existing policy")
		}
		if err := tx.Model(&c).Update("paranoia_level", 3).Error; err != nil {
			return err
		}
		if err := tx.AutoMigrate(&model.ProtectionConfig{}); err != nil {
			return err
		}
		if err := tx.First(&c, 1).Error; err != nil {
			return err
		}
		if c.ParanoiaLevel != 3 || c.ScoreThreshold != 77 {
			return errors.New("repeated migration overwrote PL selection")
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
}
