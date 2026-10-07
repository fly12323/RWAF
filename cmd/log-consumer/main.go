package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
	"github.com/fly12323/RWAF/internal/config"
	"github.com/fly12323/RWAF/internal/dao"
	"github.com/fly12323/RWAF/internal/ser/monitor"
	"github.com/fly12323/RWAF/pkg/events"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := config.LoadConfig("./configs/config.yaml"); err != nil {
		return err
	}
	if err := dao.InitDB(); err != nil {
		return err
	}
	defer dao.CloseDB()
	if err := dao.InitRedis(); err != nil {
		return err
	}
	defer dao.CloseRedis()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err := events.EnsureTopic(readyCtx, config.GetConfig().Kafka)
	cancel()
	if err != nil {
		return err
	}
	hbCtx, stopHeartbeat := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); monitor.ConsumerHeartbeat(hbCtx, config.GetConfig().Kafka.GroupID) }()
	defer func() { stopHeartbeat(); <-done }()
	return events.ConsumeGroup(ctx, dao.GetDB(), config.GetConfig().Kafka)
}
