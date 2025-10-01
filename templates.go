package flowsift

import (
	"sync"
	"time"
)

// TemplateCache кэш шаблонов
type TemplateCache struct {
	templates map[string]map[uint16]*TemplateRecord
	mutex     sync.RWMutex
	timeout   time.Duration
}

// TemplateRecord запись шаблона
type TemplateRecord struct {
	TemplateID uint16
	FieldCount uint16
	Fields     []FieldSpecifier
}

// FieldSpecifier спецификация поля
type FieldSpecifier struct {
	Type   uint16
	Length uint16
}

// FlowSet интерфейс для наборов данных
type FlowSet interface {
	GetID() uint16
	GetLength() uint16
}

// DataFlowSet набор данных
type DataFlowSet struct {
	ID      uint16
	Length  uint16
	Records []DataRecord
}

func (d *DataFlowSet) GetID() uint16     { return d.ID }
func (d *DataFlowSet) GetLength() uint16 { return d.Length }

// TemplateFlowSet набор шаблонов
type TemplateFlowSet struct {
	ID        uint16
	Length    uint16
	Templates []TemplateRecord
}

func (t *TemplateFlowSet) GetID() uint16     { return t.ID }
func (t *TemplateFlowSet) GetLength() uint16 { return t.Length }

// OptionsTemplateFlowSet набор шаблонов опций
type OptionsTemplateFlowSet struct {
	ID        uint16
	Length    uint16
	Templates []OptionsTemplateRecord
}

func (o *OptionsTemplateFlowSet) GetID() uint16     { return o.ID }
func (o *OptionsTemplateFlowSet) GetLength() uint16 { return o.Length }

// OptionsTemplateRecord шаблон опций
type OptionsTemplateRecord struct {
	TemplateID       uint16
	ScopeFieldCount  uint16
	OptionFieldCount uint16
	Fields           []FieldSpecifier
}

// DataRecord запись данных
type DataRecord struct {
	Fields map[uint16]FieldValue
}

// FieldValue значение поля
type FieldValue struct {
	Type  uint16
	Value interface{}
	Bytes []byte
}

// NewTemplateCache создает новый кэш шаблонов
func NewTemplateCache(timeout time.Duration) *TemplateCache {
	tc := &TemplateCache{
		templates: make(map[string]map[uint16]*TemplateRecord),
		timeout:   timeout,
	}
	go tc.cleanup()
	return tc
}

// Add добавляет шаблон в кэш
func (tc *TemplateCache) Add(exporter string, templateID uint16, template *TemplateRecord) {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()

	if _, exists := tc.templates[exporter]; !exists {
		tc.templates[exporter] = make(map[uint16]*TemplateRecord)
	}

	tc.templates[exporter][templateID] = template
}

// Get получает шаблон из кэша
func (tc *TemplateCache) Get(templateID uint16) *TemplateRecord {
	tc.mutex.RLock()
	defer tc.mutex.RUnlock()

	// Для простоты возвращаем первый найденный шаблон
	for _, exporterTemplates := range tc.templates {
		if template, exists := exporterTemplates[templateID]; exists {
			return template
		}
	}
	return nil
}

// GetAll возвращает все шаблоны
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

// Clear очищает кэш
func (tc *TemplateCache) Clear() {
	tc.mutex.Lock()
	defer tc.mutex.Unlock()
	tc.templates = make(map[string]map[uint16]*TemplateRecord)
}

func (tc *TemplateCache) cleanup() {
	ticker := time.NewTicker(tc.timeout)
	for range ticker.C {
		tc.mutex.Lock()
		// Упрощенная очистка
		tc.mutex.Unlock()
	}
}
