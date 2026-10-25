package main

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// BenchmarkEventBus_Publish 基准测试：100 个并发订阅者场景下的高吞吐发布性能
func BenchmarkEventBus_Publish(b *testing.B) {
	bus := NewEventBus()
	defer bus.Close()

	const subCount = 100
	var unsubs []func()
	for i := 0; i < subCount; i++ {
		ch, unsub := bus.Subscribe("bench_topic", 1000)
		unsubs = append(unsubs, unsub)
		go func(c <-chan string) {
			for range c {
			}
		}(ch)
	}
	defer func() {
		for _, u := range unsubs {
			u()
		}
	}()

	payload := `{"type":"update","data":{"rx":102400,"tx":204800}}`

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			bus.Publish("bench_topic", payload)
		}
	})
}

// BenchmarkMemoryCache_SetGet 基准测试：并发读写内存缓存
func BenchmarkMemoryCache_SetGet(b *testing.B) {
	c := NewMemoryCache(50000)
	c.Set("static_key", "static_value", 5*time.Minute)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			if i%4 == 0 {
				c.Set(fmt.Sprintf("key_%d", i%1000), "sample_val", 2*time.Minute)
			} else {
				c.Get(fmt.Sprintf("key_%d", i%1000))
			}
		}
	})
}

// BenchmarkMemoryCache_HSetHGet 基准测试：并发 Hash 操作
func BenchmarkMemoryCache_HSetHGet(b *testing.B) {
	c := NewMemoryCache(50000)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			key := fmt.Sprintf("peer:state:%d", i%500)
			if i%3 == 0 {
				c.HSet(key, map[string]interface{}{
					"rx_rate": 12.5,
					"tx_rate": 8.4,
					"online":  1,
				}, 5*time.Minute)
			} else {
				c.HGet(key, "rx_rate")
			}
		}
	})
}

// BenchmarkHealthScore 基准测试：健康评分算法
func BenchmarkHealthScore(b *testing.B) {
	now := time.Now().Unix()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		calculateHealthScore(950, 1000, now-300)
	}
}

// BenchmarkLinearRegression 基准测试：流失预测线性回归
func BenchmarkLinearRegression(b *testing.B) {
	x := make([]float64, 30)
	y := make([]float64, 30)
	for i := 0; i < 30; i++ {
		x[i] = float64(i)
		y[i] = float64(1000 - i*20 + rand.Intn(50))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		linearRegression(x, y)
	}
}

// BenchmarkDatabase_BatchInsert 基准测试：SQLite 批量事务写入
func BenchmarkDatabase_BatchInsert(b *testing.B) {
	testDir := filepath.Join(SandboxDataDir, "bench_db")
	_ = os.MkdirAll(testDir, 0755)
	dbFile := filepath.Join(testDir, "bench.db")
	_ = os.Remove(dbFile)
	defer os.RemoveAll(testDir)

	DBPath = dbFile
	_ = initDB()
	defer closeDB()

	var batch []ProcessedLog
	now := time.Now().Unix()
	for i := 0; i < 50; i++ {
		batch = append(batch, ProcessedLog{
			Timestamp: now,
			PublicKey: fmt.Sprintf("bench_key_%d", i),
			Endpoint:  "198.51.100.1:51820",
			RxBytes:   10000,
			TxBytes:   20000,
			RxRate:    1.2,
			TxRate:    3.4,
			IsOnline:  true,
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = attemptFlushDB(batch)
	}
}
