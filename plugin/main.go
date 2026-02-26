package main

import (
	"errors"

	"github.com/glebpashkov/linter_go/pkg/analyzer"
	"golang.org/x/tools/go/analysis"
)

var (
	ErrPluginConfig = errors.New("не удалось распарсить конфигурацию плагина")
	ErrPluginInit   = errors.New("не удалось создать анализатор")
)

// New — точка входа плагина для golangci-lint.
func New(conf any) ([]*analysis.Analyzer, error) {
	cfg, err := analyzer.ParseConfig(conf)
	if err != nil {
		return nil, errors.Join(ErrPluginConfig, err)
	}

	a, err := analyzer.NewAnalyzer(cfg)
	if err != nil {
		return nil, errors.Join(ErrPluginInit, err)
	}

	return []*analysis.Analyzer{a}, nil
}
