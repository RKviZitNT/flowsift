package flowsift

import (
	"fmt"
	"net"
	"time"
)

const (
	defaultTemplateTimeout = 30 * time.Minute
	versionShiftBits       = 8
	versionNetFlowV9       = 9
	versionIPFix           = 10
	minPacketHeaderLen     = 4
)

// Parser is the NetFlow/IPFIX core parser.
type Parser struct {
	templates *TemplateCache
}

// Config is the parser configuration.
type Config struct {
	TemplateTimeout time.Duration
}

// Packet is a parsing result.
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

// NewParser creates a new parser.
func NewParser(config ...Config) *Parser {
	cfg := Config{}
	if len(config) > 0 {
		cfg = config[0]
	}

	if cfg.TemplateTimeout == 0 {
		cfg.TemplateTimeout = defaultTemplateTimeout
	}

	return &Parser{
		templates: NewTemplateCache(cfg.TemplateTimeout),
	}
}

// Parse parses a NetFlow/IPFIX packet.
func (p *Parser) Parse(data []byte, sourceAddr net.IP) (*Packet, error) {
	if len(data) < minPacketHeaderLen {
		return nil, fmt.Errorf("packet too short: %d bytes", len(data))
	}

	version := getVersion(data)

	switch version {
	case versionNetFlowV9:
		return ParseNetFlowV9(data, sourceAddr, p.templates)
	case versionIPFix:
		return ParseIPFix(data, sourceAddr, p.templates)
	default:
		return nil, fmt.Errorf("unsupported version: %d", version)
	}
}

// GetTemplates returns current templates.
func (p *Parser) GetTemplates() map[uint16]*TemplateRecord {
	return p.templates.GetAll()
}

// ClearTemplates clears the template cache.
func (p *Parser) ClearTemplates() {
	p.templates.Clear()
}

// GetTemplate returns a specific template.
func (p *Parser) GetTemplate(templateID uint16) *TemplateRecord {
	return p.templates.Get(templateID)
}

func getVersion(data []byte) uint16 {
	return (uint16(data[0]) << versionShiftBits) | uint16(data[1])
}
