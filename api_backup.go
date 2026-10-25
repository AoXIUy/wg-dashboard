package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// BackupData 备份数据结构定义
type BackupData struct {
	Version    string             `json:"version"`
	ExportedAt int64              `json:"exported_at"`
	Aliases    []PeerAliasRecord  `json:"aliases"`
	Configs    []PeerConfigRecord `json:"configs"`
}

// PeerAliasRecord 别名与状态导出条目
type PeerAliasRecord struct {
	PublicKey string `json:"public_key"`
	Alias     string `json:"alias"`
	Enabled   bool   `json:"enabled"`
}

// PeerConfigRecord 配置备份导出条目
type PeerConfigRecord struct {
	PublicKey string `json:"public_key"`
	ConfName  string `json:"conf_name"`
	PeerBlock string `json:"peer_block"`
	SavedAt   int64  `json:"saved_at"`
}

// DatabaseStats 数据库存储与容量统计
type DatabaseStats struct {
	DatabasePath        string `json:"database_path"`
	FileSizeBytes       int64  `json:"file_size_bytes"`
	TrafficHistoryCount int64  `json:"traffic_history_count"`
	TrafficHourlyCount  int64  `json:"traffic_hourly_count"`
	PeerAliasesCount    int64  `json:"peer_aliases_count"`
	PeerConfigsCount    int64  `json:"peer_configs_count"`
	SandboxDirSizeBytes int64  `json:"sandbox_dir_size_bytes"`
}

// exportBackupHandler 导出所有 Peer 别名和禁用暂存配置元数据为 JSON 文件
func exportBackupHandler(c *gin.Context) {
	if db == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库未就绪"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()

	// 1. 读取所有别名
	aliasRows, err := db.QueryContext(ctx, "SELECT public_key, alias, enabled FROM peer_aliases")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("读取别名失败: %v", err)})
		return
	}
	defer aliasRows.Close()

	var aliases []PeerAliasRecord
	for aliasRows.Next() {
		var r PeerAliasRecord
		var enabledVal int
		if err := aliasRows.Scan(&r.PublicKey, &r.Alias, &enabledVal); err == nil {
			r.Enabled = (enabledVal != 0)
			aliases = append(aliases, r)
		}
	}

	// 2. 读取所有 peer_configs 暂存记录
	configRows, err := db.QueryContext(ctx, "SELECT public_key, conf_name, peer_block, saved_at FROM peer_configs ORDER BY saved_at DESC")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("读取配置暂存失败: %v", err)})
		return
	}
	defer configRows.Close()

	var configs []PeerConfigRecord
	for configRows.Next() {
		var cfg PeerConfigRecord
		if err := configRows.Scan(&cfg.PublicKey, &cfg.ConfName, &cfg.PeerBlock, &cfg.SavedAt); err == nil {
			configs = append(configs, cfg)
		}
	}

	backup := BackupData{
		Version:    "1.0",
		ExportedAt: time.Now().Unix(),
		Aliases:    aliases,
		Configs:    configs,
	}

	filename := fmt.Sprintf("wg-backup-%s-%s.json", WGInterface, time.Now().Format("20060102-150405"))
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	c.Header("Content-Type", "application/json")
	c.JSON(http.StatusOK, backup)
}

// importBackupHandler 导入 JSON 备份数据并事务化更新数据库与内存缓存
func importBackupHandler(c *gin.Context) {
	if db == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库未就绪"})
		return
	}

	var req BackupData
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("无效的备份文件格式: %v", err)})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 15*time.Second)
	defer cancel()

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("启动导入事务失败: %v", err)})
		return
	}
	defer tx.Rollback()

	importedAliases := 0
	importedConfigs := 0

	// 1. 导入并校验别名
	if len(req.Aliases) > 0 {
		aliasStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO peer_aliases (public_key, alias, enabled)
			VALUES (?, ?, ?)
			ON CONFLICT(public_key) DO UPDATE SET
				alias = excluded.alias,
				enabled = excluded.enabled
		`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("准备别名导入语句失败: %v", err)})
			return
		}
		defer aliasStmt.Close()

		for _, a := range req.Aliases {
			pk := strings.TrimSpace(a.PublicKey)
			alias := strings.TrimSpace(a.Alias)
			if pk == "" || len(alias) > MaxAliasLength {
				continue
			}
			if strings.ContainsAny(alias, "\r\n#[]=") {
				continue
			}
			enabledVal := 1
			if !a.Enabled {
				enabledVal = 0
			}
			if _, err := aliasStmt.ExecContext(ctx, pk, alias, enabledVal); err == nil {
				importedAliases++
			}
		}
	}

	// 2. 导入配置元数据
	if len(req.Configs) > 0 {
		cfgStmt, err := tx.PrepareContext(ctx, `
			INSERT INTO peer_configs (public_key, conf_name, peer_block, saved_at)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(public_key) DO UPDATE SET
				conf_name = excluded.conf_name,
				peer_block = excluded.peer_block,
				saved_at = excluded.saved_at
		`)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("准备配置导入语句失败: %v", err)})
			return
		}
		defer cfgStmt.Close()

		for _, cfg := range req.Configs {
			pk := strings.TrimSpace(cfg.PublicKey)
			if pk == "" {
				continue
			}
			savedAt := cfg.SavedAt
			if savedAt <= 0 {
				savedAt = time.Now().Unix()
			}
			if _, err := cfgStmt.ExecContext(ctx, pk, cfg.ConfName, cfg.PeerBlock, savedAt); err == nil {
				importedConfigs++
			}
		}
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("提交导入数据失败: %v", err)})
		return
	}

	// 立即刷新内存别名缓存
	if aliasCache != nil {
		_ = aliasCache.Refresh(context.Background())
	}

	c.JSON(http.StatusOK, gin.H{
		"status":           "ok",
		"message":          "备份数据导入成功",
		"imported_aliases": importedAliases,
		"imported_configs": importedConfigs,
	})
}

// databaseStatsHandler 返回 SQLite 数据库及沙盒存储容量统计
func databaseStatsHandler(c *gin.Context) {
	if db == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "数据库未就绪"})
		return
	}

	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	stats := DatabaseStats{
		DatabasePath: DBPath,
	}

	if fi, err := os.Stat(DBPath); err == nil {
		stats.FileSizeBytes = fi.Size()
	}

	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM traffic_history").Scan(&stats.TrafficHistoryCount)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM traffic_hourly").Scan(&stats.TrafficHourlyCount)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM peer_aliases").Scan(&stats.PeerAliasesCount)
	_ = db.QueryRowContext(ctx, "SELECT COUNT(*) FROM peer_configs").Scan(&stats.PeerConfigsCount)

	// 计算沙盒目录总大小
	var dirSize int64
	_ = filepath.Walk(SandboxDataDir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			dirSize += info.Size()
		}
		return nil
	})
	stats.SandboxDirSizeBytes = dirSize

	c.JSON(http.StatusOK, stats)
}
