package main

import (
	"context"
	"fmt"
	"slices"
)

func (e *Engine) sourceCapability(ctx context.Context, name string) SourceCapability {
	c := SourceCapability{Name: name}
	if builtinPassive(name) {
		c.Enabled = true
		c.ScopeModes = []string{"exact", "subdomains", "descendants"}
		c.EvidenceOnly = true
		return c
	}
	if e.Store.Plugins == nil {
		if name == "subfinder" {
			c.Enabled = true
			c.ScopeModes = []string{"subdomains", "descendants"}
		}
		return c
	}
	m, _, enabled, err := e.Store.pluginConfig(ctx, name)
	if err != nil || !enabled || m.Active {
		return c
	}
	c.Enabled = true
	c.ScopeModes = slices.Clone(m.ScopeModes)
	return c
}

func (e *Engine) collectorCapabilities(ctx context.Context) []SourceCapability {
	names := []string{"crtsh", "certspotter", "fofa", "hunter"}
	if e.Store.Plugins == nil {
		names = append(names, "subfinder")
	} else {
		names = append(names, e.Store.Plugins.names()...)
	}
	out := make([]SourceCapability, 0, len(names))
	for _, name := range names {
		out = append(out, e.sourceCapability(ctx, name))
	}
	return out
}

func (e *Engine) validateSourceSetup(ctx context.Context, scopeMode string, sources []string, collectionMode string) error {
	if err := e.validSources(sources); err != nil {
		return err
	}
	if _, err := validateCollectionMode(collectionMode, sources); err != nil {
		return err
	}
	for _, name := range sources {
		if reason := e.sourceCapability(ctx, name).BlockReason(scopeMode, collectionMode); reason != "" {
			return executionFailure("source_incompatible", fmt.Sprintf("%s：%s", name, reason), false)
		}
	}
	return nil
}
