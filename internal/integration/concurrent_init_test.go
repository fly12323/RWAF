package integration

import (
	"context"
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/dao"
)

func TestConcurrentIndexInitialization(t *testing.T) {
	if os.Getenv("WAF_INTEGRATION") != "1" {
		t.Skip("requires disposable PostgreSQL")
	}
	for k, v := range map[string]string{"DB_HOST": "127.0.0.1", "DB_PORT": "15432", "DB_USER": "waf_test", "DB_PASSWORD": "waf-test-only", "DB_NAME": "waf_test"} {
		t.Setenv(k, v)
	}
	if err := config.LoadConfig("../../configs/config.yaml"); err != nil {
		t.Fatal(err)
	}
	if database := os.Getenv("WAF_INDEX_INIT_HELPER"); database != "" {
		config.GetConfig().Database.Database = database
		if err := dao.InitDB(); err != nil {
			t.Fatal(err)
		}
		dao.CloseDB()
		return
	}
	db, err := gorm.Open(postgres.Open(config.GetConfig().Database.DSN()), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	name := fmt.Sprintf("waf_index_probe_%d", time.Now().UnixNano())
	if err := db.Exec("CREATE DATABASE " + name).Error; err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Exec("DROP DATABASE " + name + " WITH (FORCE)").Error; err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConcurrentIndexInitialization$", "-test.v")
			cmd.Env = append(os.Environ(), "WAF_INDEX_INIT_HELPER="+name)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("concurrent initialization: %v\n%s", err, output)
			}
		}()
	}
	wg.Wait()
}
