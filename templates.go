package flowsift

import (
	"sync"
	"time"
)

// TemplateCache stores templates per exporter with periodic cleanup.
type TemplateCache struct {
	templates map[string]map[uint16]*TemplateRecord
	mutex     sync.RWMutex
	timeout   time.Duration
}

// TemplateRecord describes a template entry.
type TemplateRecord struct {
	TemplateID uint16
	FieldCount uint16
	Fields     []FieldSpecifier
}

// FieldSpecifier describes a field in a template.
type FieldSpecifier struct {
	Type   uint16
	Length uint16
}

// FlowSet is the interface for data sets.
type FlowSet interface {
	GetID() uint16
	GetLength() uint16
}

// DataFlowSet represents a data set.
type DataFlowSet struct {
	ID      uint16
	Length  uint16
	Records []DataRecord
}

// GetID returns the FlowSet ID.
func (d *DataFlowSet) GetID() uint16     { return d.ID }
// GetLength returns the FlowSet length.
func (d *DataFlowSet) GetLength() uint16 { return d.Length }

// TemplateFlowSet represents a set of templates.
type TemplateFlowSet struct {
	ID        uint16
	Length    uint16
	Templates []TemplateRecord
}

// GetID returns the FlowSet ID.
func (t *TemplateFlowSet) GetID() uint16     { return t.ID }
// GetLength returns the FlowSet length.
func (t *TemplateFlowSet) GetLength() uint16 { return t.Length }

// OptionsTemplateFlowSet represents a set of option templates.
type OptionsTemplateFlowSet struct {
	ID        uint16
	Length    uint16
	Templates []OptionsTemplateRecord
}

// GetID returns the FlowSet ID.
func (o *OptionsTemplateFlowSet) GetID() uint16     { return o.ID }
// GetLength returns the FlowSet length.
func (o *OptionsTemplateFlowSet) GetLength() uint16 { return o.Length }

// OptionsTemplateRecord describes an options template.
type OptionsTemplateRecord struct {
	TemplateID       uint16
	ScopeFieldCount  uint16
	OptionFieldCount uint16
	Fields           []FieldSpecifier
}

// DataRecord represents parsed field values for a single record.
type DataRecord struct {
	Fields map[uint16]FieldValue
}

// FieldValue is a parsed field value with raw bytes.
type FieldValue struct {
	Type  uint16
	Value interface{}
	Bytes []byte
}

// NewTemplateCache creates a new template cache.
func NewTemplateCache(timeout time.Duration) *TemplateCache {
	tc := &TemplateCache{
		templates: make(map[string]map[uint16]*TemplateRecord),
		timeout:   timeout,
	}
	go tc.cleanup()
	return tc
}

// Add adds a template to the cache.
func (tc *TemplateCache) Add(exporter string, templateID uint16, template *TemplateRecord) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	if _, exists := tc.templates[exporter]; !exists {
		tc.templates[exporter] = make(map[uint16]*TemplateRecord)
	}

	tc.templates[exporter][templateID] = template
}

// Get returns a template by ID from any exporter.
func (tc *TemplateCache) Get(templateID uint16) *TemplateRecord {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	for _, exporterTemplates := range tc.templates {
		if template, exists := exporterTemplates[templateID]; exists {
			return template
		}
	}
	return nil
}

// GetAll returns all templates from all exporters in a flat map.
func (tc *TemplateCache) GetAll() map[uint16]*TemplateRecord {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	result := make(map[uint16]*TemplateRecord)
	for _, exporterTemplates := range tc.templates {
		for templateID, template := range exporterTemplates {
			result[templateID] = template
		}
	}
	return result
}

// Clear clears all templates from the cache.
func (tc *TemplateCache) Clear() {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.templates = make(map[string]map[uint16]*TemplateRecord)
}

func (tc *TemplateCache) cleanup() {
	ticker := time.NewTicker(tc.timeout)
	for range ticker.C {
		tc.mutex.Lock()
		tc.Clear()
		tc.mutex.Unlock()
	}
}
