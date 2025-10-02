package flowsift

import (
	"fmt"
	"net"
	"time"
)

// NetFlow/IPFix core parser
type Parser struct {
	templates *TemplateCache
}

// Parser configuration
type Config struct {
	TemplateTimeout time.Duration
}

// Parsing result
type Packet struct {
	Version    uint16
	Count      uint16
	SysUptime  uint32
	UnixSec    uint32
	Sequence   uint32
	SourceID   uint32
	SourceAddr net.IP
	Timestamp  time.Time
	FlowSets   []FlowSet
}

// Creates a new parser
func NewParser(config ...Config) *Parser {
	cfg := Config{}
	if len(config) > 0 {
		cfg = config[0]
	}

	if cfg.TemplateTimeout == 0 {
		cfg.TemplateTimeout = 30 * time.Minute
	}

	return &Parser{
		templates: NewTemplateCache(cfg.TemplateTimeout),
	}
}

// Parses a NetFlow/IPFix packet
func (p *Parser) Parse(data []byte, sourceAddr net.IP) (*Packet, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	version := getVersion(data)

	switch version {
	case 9:
		return ParseNetFlowV9(data, sourceAddr, p.templates)
	case 10:
		return ParseIPFix(data, sourceAddr, p.templates)
	default:
		return nil, fmt.Errorf("unsupported version: %d", version)
	}
}

// Returns current templates
func (p *Parser) GetTemplates() map[uint16]*TemplateRecord {
	return p.templates.GetAll()
}

// Clears the template cache
func (p *Parser) ClearTemplates() {
	p.templates.Clear()
}

// Returns a specific template
func (p *Parser) GetTemplate(templateID uint16) *TemplateRecord {
	return p.templates.Get(templateID)
}

func getVersion(data []byte) uint16 {
	return (uint16(data[0]) << 8) | uint16(data[1])
}
