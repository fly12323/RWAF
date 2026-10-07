package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/spf13/viper"
)

// Config 全局配置结构体
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	WAF      WAFConfig      `mapstructure:"waf"`
	Log      LogConfig      `mapstructure:"log"`
	Proxy    ProxyConfig    `mapstructure:"proxy"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	Redis    RedisConfig    `mapstructure:"redis"`
	Kafka    KafkaConfig    `mapstructure:"kafka"`
}

type KafkaConfig struct {
	PublisherWorkers int      `mapstructure:"publisher_workers"`
	ConsumerWorkers  int      `mapstructure:"consumer_workers"`
	SpoolDir         string   `mapstructure:"spool_dir"`
	SpoolMaxBytes    int64    `mapstructure:"spool_max_bytes"`
	SpoolSyncMs      int      `mapstructure:"spool_sync_ms"`
	Brokers          []string `mapstructure:"brokers"`
	Topic            string   `mapstructure:"topic"`
	GroupID          string   `mapstructure:"group_id"`
	QueueSize        int      `mapstructure:"queue_size"`
	BatchSize        int      `mapstructure:"batch_size"`
	FlushIntervalMs  int      `mapstructure:"flush_interval_ms"`
	MaxEventBytes    int      `mapstructure:"max_event_bytes"`
}

// ServerConfig 服务器配置
type ServerConfig struct {
	Port         int    `mapstructure:"port"`
	Mode         string `mapstructure:"mode"`
	ReadTimeout  int    `mapstructure:"read_timeout"`
	WriteTimeout int    `mapstructure:"write_timeout"`
}

// JWTConfig JWT 配置
type JWTConfig struct {
	Secret     string `mapstructure:"secret"`
	ExpireTime int    `mapstructure:"expire_time"`
	Issuer     string `mapstructure:"issuer"`
}

// RedisConfig Redis 配置
type RedisConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
}

// DatabaseConfig 数据库配置
type DatabaseConfig struct {
	Host            string `mapstructure:"host"`
	Port            int    `mapstructure:"port"`
	Username        string `mapstructure:"username"`
	Password        string `mapstructure:"password"`
	Database        string `mapstructure:"database"`
	Charset         string `mapstructure:"charset"`
	SSLMode         string `mapstructure:"sslmode"`
	MaxIdleConns    int    `mapstructure:"max_idle_conns"`
	MaxOpenConns    int    `mapstructure:"max_open_conns"`
	ConnMaxLifetime int    `mapstructure:"conn_max_lifetime"`
}

// DSN 返回数据库连接字符串
func (d *DatabaseConfig) DSN() string {
	u := url.URL{Scheme: "postgres", User: url.UserPassword(d.Username, d.Password),
		Host: net.JoinHostPort(d.Host, strconv.Itoa(d.Port)), Path: "/" + d.Database}
	q := u.Query()
	q.Set("sslmode", d.SSLMode)
	// GORM reads the timezone directly from DSN; keep this fixed value unescaped.
	u.RawQuery = q.Encode() + "&timezone=Asia/Shanghai"
	return u.String()
}

// WAFConfig WAF引擎配置
type WAFConfig struct {
	EngineMode              string `mapstructure:"engine_mode"`
	RulesDir                string `mapstructure:"rules_dir"`
	CrsDir                  string `mapstructure:"crs_dir"`
	CustomRulesDir          string `mapstructure:"custom_rules_dir"`
	RequestBodyLimit        int64  `mapstructure:"request_body_limit"`
	RequestBodyNoFilesLimit int64  `mapstructure:"request_body_no_files_limit"`
	ResponseBodyLimit       int64  `mapstructure:"response_body_limit"`
	DefaultScoreThreshold   int    `mapstructure:"default_score_threshold"`
	DefaultMode             string `mapstructure:"default_mode"`
}

// LogConfig 日志配置
type LogConfig struct {
	RetentionDays          int     `mapstructure:"retention_days"`
	CleanupIntervalMinutes int     `mapstructure:"cleanup_interval_minutes"`
	CleanupBatchSize       int     `mapstructure:"cleanup_batch_size"`
	StatisticsCacheSeconds int     `mapstructure:"statistics_cache_seconds"`
	Level                  string  `mapstructure:"level"`
	Format                 string  `mapstructure:"format"`
	Output                 string  `mapstructure:"output"`
	File                   LogFile `mapstructure:"file"`
}

// LogFile 日志文件配置
type LogFile struct {
	Enabled    bool `mapstructure:"enabled"`
	MaxSize    int  `mapstructure:"max_size"`
	MaxBackups int  `mapstructure:"max_backups"`
	MaxAge     int  `mapstructure:"max_age"`
	Compress   bool `mapstructure:"compress"`
}

// ProxyConfig 反向代理配置
type ProxyConfig struct {
	TLSKeyFile          string `mapstructure:"tls_key_file"`
	ConnectTimeout      int    `mapstructure:"connect_timeout"`
	ReadTimeout         int    `mapstructure:"read_timeout"`
	WriteTimeout        int    `mapstructure:"write_timeout"`
	IdleTimeout         int    `mapstructure:"idle_timeout"`
	MaxIdleConns        int    `mapstructure:"max_idle_conns"`
	MaxIdleConnsPerHost int    `mapstructure:"max_idle_conns_per_host"`
}

// GlobalConfig 全局配置变量
var GlobalConfig *Config

// LoadConfig 加载配置文件
func LoadConfig(configPath string) error {
	v := viper.New()

	v.SetConfigFile(configPath)
	v.SetConfigType("yaml")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.sslmode", "disable")
	v.SetDefault("kafka.brokers", []string{"127.0.0.1:9092"})
	v.SetDefault("kafka.topic", "waf-events")
	v.SetDefault("kafka.group_id", "waf-log-writer")
	v.SetDefault("kafka.queue_size", 4096)
	v.SetDefault("kafka.batch_size", 500)
	v.SetDefault("kafka.flush_interval_ms", 200)
	v.SetDefault("kafka.max_event_bytes", 262144)
	v.SetDefault("kafka.publisher_workers", 3)
	v.SetDefault("kafka.consumer_workers", 3)
	v.SetDefault("kafka.spool_dir", "./data/event-spool")
	v.SetDefault("kafka.spool_max_bytes", 1073741824)
	v.SetDefault("kafka.spool_sync_ms", 5)
	v.SetDefault("log.retention_days", 30)
	v.SetDefault("log.cleanup_interval_minutes", 60)
	v.SetDefault("log.cleanup_batch_size", 1000)
	v.SetDefault("log.statistics_cache_seconds", 5)
	v.SetDefault("proxy.tls_key_file", "./data/tls/master.key")

	if err := v.ReadInConfig(); err != nil {
		return fmt.Errorf("读取配置文件失败: %w", err)
	}

	// 支持环境变量覆盖配置
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 手动处理环境变量覆盖
	for key, target := range map[string]*string{"DB_USER": &cfg.Database.Username,
		"DB_PASSWORD": &cfg.Database.Password, "DB_NAME": &cfg.Database.Database,
		"DB_SSLMODE": &cfg.Database.SSLMode, "REDIS_PASSWORD": &cfg.Redis.Password,
		"JWT_SECRET": &cfg.JWT.Secret} {
		if value, ok := os.LookupEnv(key); ok {
			*target = value
		}
	}
	if value := os.Getenv("KAFKA_BROKERS"); value != "" {
		cfg.Kafka.Brokers = strings.Split(value, ",")
	}
	if host := os.Getenv("DB_HOST"); host != "" {
		cfg.Database.Host = host
	}
	if port := os.Getenv("DB_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			cfg.Database.Port = p
		}
	}
	if host := os.Getenv("REDIS_HOST"); host != "" {
		cfg.Redis.Host = host
	}
	if port := os.Getenv("REDIS_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			cfg.Redis.Port = p
		}
	}

	if cfg.Kafka.QueueSize <= 0 || cfg.Kafka.BatchSize <= 0 || cfg.Kafka.BatchSize > 500 ||
		cfg.Kafka.FlushIntervalMs <= 0 || cfg.Kafka.MaxEventBytes <= 0 || cfg.Kafka.MaxEventBytes > 524288 ||
		cfg.Kafka.Topic == "" || cfg.Kafka.GroupID == "" || len(cfg.Kafka.Brokers) == 0 {
		return fmt.Errorf("Kafka 配置无效")
	}
	if cfg.Kafka.PublisherWorkers < 1 || cfg.Kafka.PublisherWorkers > 16 || cfg.Kafka.ConsumerWorkers < 1 || cfg.Kafka.ConsumerWorkers > 16 || cfg.Kafka.SpoolDir == "" || cfg.Kafka.SpoolMaxBytes < int64(cfg.Kafka.MaxEventBytes)*int64(cfg.Kafka.PublisherWorkers) || cfg.Kafka.SpoolSyncMs < 1 || cfg.Kafka.SpoolSyncMs > 100 {
		return fmt.Errorf("日志磁盘缓冲或 worker 配置无效")
	}
	if cfg.Log.RetentionDays < 0 || cfg.Log.CleanupIntervalMinutes < 1 || cfg.Log.CleanupBatchSize < 1 || cfg.Log.CleanupBatchSize > 10000 || cfg.Log.StatisticsCacheSeconds < 0 || cfg.Log.StatisticsCacheSeconds > 300 {
		return fmt.Errorf("日志保留/清理/缓存配置无效")
	}
	if cfg.WAF.RequestBodyLimit <= 0 {
		return fmt.Errorf("request_body_limit 必须大于零")
	}
	if cfg.WAF.EngineMode != "On" && cfg.WAF.EngineMode != "Off" && cfg.WAF.EngineMode != "DetectionOnly" {
		return fmt.Errorf("无效的 WAF engine_mode")
	}
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		return err
	}
	time.Local = location
	GlobalConfig = &cfg

	return nil
}

// GetConfig 获取全局配置
func GetConfig() *Config {
	return GlobalConfig
}
