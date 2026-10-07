package dao

import (
	"fmt"
	"time"

	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/model"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// DB 全局数据库连接
var DB *gorm.DB

// InitDB 初始化数据库连接
func InitDB() error {
	cfg := config.GetConfig().Database

	// 配置 GORM 日志
	var gormLogger logger.Interface
	if config.GetConfig().Server.Mode == "debug" {
		gormLogger = logger.Default.LogMode(logger.Info)
	} else {
		gormLogger = logger.Default.LogMode(logger.Warn)
	}

	// 打开数据库连接
	db, err := gorm.Open(postgres.Open(cfg.DSN()), &gorm.Config{
		Logger: gormLogger,
	})
	if err != nil {
		return fmt.Errorf("连接数据库失败: %w", err)
	}

	// 获取底层 SQL DB
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("获取数据库连接池失败: %w", err)
	}

	// 设置连接池参数
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)                                    // 最大空闲连接数
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)                                    // 最大打开连接数
	sqlDB.SetConnMaxLifetime(time.Duration(cfg.ConnMaxLifetime) * time.Second) // 连接最大生命周期

	// 测试连接
	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("数据库连接测试失败: %w", err)
	}

	// 保存到全局变量
	DB = db

	// 自动迁移模型
	if err := db.Transaction(func(migration *gorm.DB) error {
		if err := migration.Exec("SELECT pg_advisory_xact_lock(73921401)").Error; err != nil {
			return err
		}
		if err := migration.AutoMigrate(
			&model.User{}, &model.Site{}, &model.Rule{}, &model.RuleGroup{},
			&model.Whitelist{}, &model.SystemConfig{}, &model.ProtectionConfig{},
			&model.RequestLog{}, &model.RuleMatch{}, &model.CrawlerLog{}, &model.ProcessedEvent{},
			&model.OperationLog{},
			&model.IPBlacklist{},
			&model.IPWhitelist{},
			&model.WeakPasswordConfig{}, &model.WeakPasswordEvent{}, &model.MonitorConfig{}, &model.Alert{},
		); err != nil {
			return err
		}
		return initializeProtection(migration)
	}); err != nil {
		return fmt.Errorf("数据库迁移失败: %w", err)
	}
	if err := db.Connection(func(conn *gorm.DB) error {
		// A blocking SELECT holds a snapshot while waiting for this lock.
		// CREATE INDEX CONCURRENTLY waits for those snapshots, producing a
		// deadlock. Poll the nonblocking lock between completed statements.
		for {
			var acquired bool
			if err := conn.Raw("SELECT pg_try_advisory_lock(73921403)").Scan(&acquired).Error; err != nil {
				return err
			}
			if acquired {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		defer conn.Exec("SELECT pg_advisory_unlock(73921403)")
		for _, statement := range []string{
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_site_time ON request_logs (site_id, created_at DESC, id DESC)",
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_action_time ON request_logs (action, created_at DESC, id DESC)",
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_ip_time ON request_logs (client_ip, created_at DESC, id DESC)",
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_attack_time ON request_logs (attack_type, created_at DESC)",
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_rule_match_time ON rule_matches (created_at, rule_id)",
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_crawler_retention ON crawler_logs (created_at, id)",
			"CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_weak_retention ON weak_password_events (created_at, id)",
		} {
			if err := conn.Exec(statement).Error; err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("日志索引创建失败: %w", err)
	}
	fmt.Println("✓ 数据库迁移成功")

	fmt.Println("数据库连接成功")
	return nil
}

// GetDB 获取数据库连接
func GetDB() *gorm.DB {
	return DB
}

// CloseDB 关闭数据库连接
func CloseDB() error {
	if DB != nil {
		sqlDB, err := DB.DB()
		if err != nil {
			return err
		}
		return sqlDB.Close()
	}
	return nil
}
