package flowsift

import (
	"sync"
	"time"
)

// Template cache
type TemplateCache struct {
	templates map[string]map[uint16]*TemplateRecord
	mutex     sync.RWMutex
	timeout   time.Duration
}

// Template entry
type TemplateRecord struct {
	TemplateID uint16
	FieldCount uint16
	Fields     []FieldSpecifier
}

// Field specification
type FieldSpecifier struct {
	Type   uint16
	Length uint16
}

// Interface for data sets
type FlowSet interface {
	GetID() uint16
	GetLength() uint16
}

// Data set
type DataFlowSet struct {
	ID      uint16
	Length  uint16
	Records []DataRecord
}

func (d *DataFlowSet) GetID() uint16     { return d.ID }
func (d *DataFlowSet) GetLength() uint16 { return d.Length }

// Set of templates
type TemplateFlowSet struct {
	ID        uint16
	Length    uint16
	Templates []TemplateRecord
}

func (t *TemplateFlowSet) GetID() uint16     { return t.ID }
func (t *TemplateFlowSet) GetLength() uint16 { return t.Length }

// Set of option templates
type OptionsTemplateFlowSet struct {
	ID        uint16
	Length    uint16
	Templates []OptionsTemplateRecord
}

func (o *OptionsTemplateFlowSet) GetID() uint16     { return o.ID }
func (o *OptionsTemplateFlowSet) GetLength() uint16 { return o.Length }

// Options template
type OptionsTemplateRecord struct {
	TemplateID       uint16
	ScopeFieldCount  uint16
	OptionFieldCount uint16
	Fields           []FieldSpecifier
}

// Data recording
type DataRecord struct {
	Fields map[uint16]FieldValue
}

// Field value
type FieldValue struct {
	Type  uint16
	Value interface{}
	Bytes []byte
}

// Creates a new template cache
func NewTemplateCache(timeout time.Duration) *TemplateCache {
	tc := &TemplateCache{
		templates: make(map[string]map[uint16]*TemplateRecord),
		timeout:   timeout,
	}
	go tc.cleanup()
	return tc
}

// Adds a template to the cache
func (tc *TemplateCache) Add(exporter string, templateID uint16, template *TemplateRecord) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	if _, exists := tc.templates[exporter]; !exists {
		tc.templates[exporter] = make(map[uint16]*TemplateRecord)
	}

	tc.templates[exporter][templateID] = template
}

// Gets the template from the cache
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

// Returns all patterns
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

// Clears the cache
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
