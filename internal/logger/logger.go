package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"network-monitor/internal/models"
)

// Logger 日志记录器
type Logger struct {
	mu       sync.Mutex
	logDir   string
	scanLog  []*models.ScanLog
	alertLog []*models.Alert
	attackLog []*models.AttackLog
	opLog    []*models.OperationLog
}

// New 创建日志记录器
func New(dir string) *Logger {
	os.MkdirAll(dir, 0755)
	return &Logger{
		logDir:   dir,
		scanLog:  make([]*models.ScanLog, 0),
		alertLog: make([]*models.Alert, 0),
		attackLog: make([]*models.AttackLog, 0),
		opLog:    make([]*models.OperationLog, 0),
	}
}

// LogScan 记录扫描日志
func (l *Logger) LogScan(devices []*models.Device) {
	l.mu.Lock()
	defer l.mu.Unlock()

	online := 0
	for _, d := range devices {
		if d.Status == "online" {
			online++
		}
	}

	log := &models.ScanLog{
		Timestamp:    time.Now(),
		TotalDevices: len(devices),
		OnlineDevices: online,
	}

	l.scanLog = append(l.scanLog, log)
	// Save devices separately if needed
	l.saveToFile("scan", map[string]interface{}{
		"timestamp": log.Timestamp,
		"total_devices": log.TotalDevices,
		"online_devices": log.OnlineDevices,
	})
}

// LogAlert 记录告警
func (l *Logger) LogAlert(alert *models.Alert) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.alertLog = append(l.alertLog, alert)
	l.saveToFile("alert", alert)
}

// LogAttack 记录攻击
func (l *Logger) LogAttack(attack *models.AttackAlert) {
	l.mu.Lock()
	defer l.mu.Unlock()

	log := &models.AttackLog{
		Timestamp:  time.Now(),
		AttackType: attack.AttackType,
		SourceIP:   attack.SourceIP,
		TargetIP:   attack.TargetIP,
		ThreatLevel: attack.ThreatLevel,
		Details:    attack.Details,
	}

	l.attackLog = append(l.attackLog, log)
	l.saveToFile("attack", log)
}

// LogOperation 记录操作
func (l *Logger) LogOperation(operation string, target string, details string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	log := &models.OperationLog{
		Timestamp: time.Now(),
		Operation: operation,
		Target:    target,
		Details:   details,
	}

	l.opLog = append(l.opLog, log)
	l.saveToFile("operation", log)
}

// 保存到文件
func (l *Logger) saveToFile(prefix string, data interface{}) {
	filename := filepath.Join(l.logDir, fmt.Sprintf("%s_%s.json", prefix, time.Now().Format("2006-01-02")))
	
	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	bytes, err := json.Marshal(data)
	if err != nil {
		return
	}
	f.Write(append(bytes, '\n'))
}

// GetScanLogs 获取扫描日志
func (l *Logger) GetScanLogs(limit int) []*models.ScanLog {
	l.mu.Lock()
	defer l.mu.Unlock()

	if limit > len(l.scanLog) {
		limit = len(l.scanLog)
	}
	result := make([]*models.ScanLog, limit)
	copy(result, l.scanLog[len(l.scanLog)-limit:])
	return result
}

// GetAlertLogs 获取告警日志
func (l *Logger) GetAlertLogs(limit int) []*models.Alert {
	l.mu.Lock()
	defer l.mu.Unlock()

	if limit > len(l.alertLog) {
		limit = len(l.alertLog)
	}
	result := make([]*models.Alert, limit)
	copy(result, l.alertLog[len(l.alertLog)-limit:])
	return result
}

// GetAttackLogs 获取攻击日志
func (l *Logger) GetAttackLogs(limit int) []*models.AttackLog {
	l.mu.Lock()
	defer l.mu.Unlock()

	if limit > len(l.attackLog) {
		limit = len(l.attackLog)
	}
	result := make([]*models.AttackLog, limit)
	copy(result, l.attackLog[len(l.attackLog)-limit:])
	return result
}

// GetOperationLogs 获取操作日志
func (l *Logger) GetOperationLogs(limit int) []*models.OperationLog {
	l.mu.Lock()
	defer l.mu.Unlock()

	if limit > len(l.opLog) {
		limit = len(l.opLog)
	}
	result := make([]*models.OperationLog, limit)
	copy(result, l.opLog[len(l.opLog)-limit:])
	return result
}

// ClearLogs 清除旧日志
func (l *Logger) ClearLogs(days int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().AddDate(0, 0, -days)
	
	var newScanLog []*models.ScanLog
	for _, log := range l.scanLog {
		if log.Timestamp.After(cutoff) {
			newScanLog = append(newScanLog, log)
		}
	}
	l.scanLog = newScanLog

	var newAlertLog []*models.Alert
	for _, log := range l.alertLog {
		if log.Timestamp.After(cutoff) {
			newAlertLog = append(newAlertLog, log)
		}
	}
	l.alertLog = newAlertLog

	// 删除旧文件
	files, _ := filepath.Glob(filepath.Join(l.logDir, "*.json"))
	for _, f := range files {
		info, _ := os.Stat(f)
		if info != nil && info.ModTime().Before(cutoff) {
			os.Remove(f)
		}
	}
}
