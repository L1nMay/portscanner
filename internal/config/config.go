package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type TelegramConfig struct {
	Enabled  bool   `yaml:"enabled"`
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
}

type WebUIConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

type Config struct {
	MasscanPath string   `yaml:"masscan_path"`
	Targets     []string `yaml:"targets"`
	Ports       string   `yaml:"ports"`
	Rate        int      `yaml:"rate"`

	WaitSeconds int    `yaml:"wait_seconds"`
	Interface   string `yaml:"interface"`

	DBPath            string         `yaml:"db_path"`
	ConnectTimeoutSec int            `yaml:"connect_timeout_seconds"`
	ReadTimeoutSec    int            `yaml:"read_timeout_seconds"`
	BannerMaxBytes    int            `yaml:"banner_max_bytes"`
	Telegram          TelegramConfig `yaml:"telegram"`
	ScanName          string         `yaml:"scan_name"`

	WebUI       WebUIConfig `yaml:"webui"`
	AutoTargets bool        `yaml:"auto_targets"`
	UserDefined bool        `yaml:"-"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// defaults
	if cfg.MasscanPath == "" {
		cfg.MasscanPath = "masscan"
	}
	if cfg.Rate <= 0 {
		cfg.Rate = 1000
	}
	if cfg.ConnectTimeoutSec <= 0 {
		cfg.ConnectTimeoutSec = 3
	}
	if cfg.ReadTimeoutSec <= 0 {
		cfg.ReadTimeoutSec = 3
	}
	if cfg.BannerMaxBytes <= 0 {
		cfg.BannerMaxBytes = 1024
	}
	if cfg.ScanName == "" {
		cfg.ScanName = "Port scanner"
	}
	if cfg.WebUI.Listen == "" {
		cfg.WebUI.Listen = "127.0.0.1:8088"
	}

	return &cfg, nil
}

func (c *Config) ConnectTimeout() time.Duration {
	return time.Duration(c.ConnectTimeoutSec) * time.Second
}

func (c *Config) ReadTimeout() time.Duration {
	return time.Duration(c.ReadTimeoutSec) * time.Second
}
