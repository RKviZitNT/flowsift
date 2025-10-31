// Package flowsift provides a NetFlow v9 and IPFIX parser with template caching.
package flowsift

import (
    "encoding/binary"
    "fmt"
    "net"
    "time"
)

const (
    netFlowV9HeaderLen = 20
    ipfixHeaderLen     = 16
    flowSetHeaderLen   = 4
    dataFlowSetMinID   = 256
    padAlignment       = 4

    flowSetIDTemplateV9       uint16 = 0
    flowSetIDOptionsTemplateV9 uint16 = 1
    flowSetIDTemplateIPFix    uint16 = 2
    flowSetIDOptionsIPFix     uint16 = 3
    byteShiftBits                    = 8
)

type flowSetHandler func(flowSetID uint16, flowSetData []byte) (FlowSet, error)

func parseFlowSets(data []byte, startOffset int, handler flowSetHandler) ([]FlowSet, error) {
    var result []FlowSet
    offset := startOffset
    for offset+flowSetHeaderLen <= len(data) {
        flowSetID := binary.BigEndian.Uint16(data[offset : offset+2])
        length := binary.BigEndian.Uint16(data[offset+2 : offset+4])

        if length < flowSetHeaderLen {
            return nil, fmt.Errorf("invalid FlowSet length: %d", length)
        }

        if offset+int(length) > len(data) {
            return nil, fmt.Errorf("FlowSet length %d exceeds packet size", length)
        }

        flowSetData := data[offset : offset+int(length)]

        fs, err := handler(flowSetID, flowSetData)
        if err != nil {
            return nil, err
        }
        if fs != nil {
            result = append(result, fs)
        }

        offset += int(length)
    }
    return result, nil
}

// ParseNetFlowV9 parses a NetFlow v9 packet.
func ParseNetFlowV9(data []byte, sourceAddr net.IP, templates *TemplateCache) (*Packet, error) {
    if len(data) < netFlowV9HeaderLen {
        return nil, fmt.Errorf("NetFlow v9 packet too short: %d bytes", len(data))
    }

    header := parseNetFlowV9Header(data[:netFlowV9HeaderLen])

    packet := &Packet{
        Version:    header.Version,
        Count:      header.Count,
        SysUptime:  header.SysUptime,
        UnixSec:    header.UnixSec,
        Sequence:   header.Sequence,
        SourceID:   header.SourceID,
        SourceAddr: sourceAddr,
        Timestamp:  time.Unix(int64(header.UnixSec), 0),
        FlowSets:   make([]FlowSet, 0),
    }

    handler := func(flowSetID uint16, flowSetData []byte) (FlowSet, error) {
        switch {
        case flowSetID == flowSetIDTemplateV9:
            fs, err := parseTemplateFlowSet(flowSetData)
            if err == nil {
                for _, template := range fs.Templates {
                    templates.Add(sourceAddr.String(), template.TemplateID, &template)
                }
            }
            return fs, err
        case flowSetID == flowSetIDOptionsTemplateV9:
            return parseOptionsTemplateFlowSet(flowSetData)
        case flowSetID >= dataFlowSetMinID:
            template := templates.Get(flowSetID)
            if template != nil {
                return parseDataFlowSet(flowSetData, flowSetID, template)
            }
            return nil, fmt.Errorf("template not found for FlowSet ID %d (source: %s)", flowSetID, sourceAddr.String())
        default:
            return nil, fmt.Errorf("unknown FlowSet ID: %d", flowSetID)
        }
    }

    flowSets, err := parseFlowSets(data, netFlowV9HeaderLen, handler)
    if err != nil {
        return nil, err
    }
    packet.FlowSets = append(packet.FlowSets, flowSets...)
    return packet, nil
}

// ParseIPFix parses an IPFIX packet.
func ParseIPFix(data []byte, sourceAddr net.IP, templates *TemplateCache) (*Packet, error) {
    if len(data) < ipfixHeaderLen {
        return nil, fmt.Errorf("IPFix packet too short: %d bytes", len(data))
    }

    header := parseIPFixHeader(data[:ipfixHeaderLen])

    packet := &Packet{
        Version:    header.Version,
        Sequence:   header.Sequence,
        SourceID:   header.ObservationDomainID,
        SourceAddr: sourceAddr,
        Timestamp:  time.Unix(int64(header.ExportTime), 0),
        FlowSets:   make([]FlowSet, 0),
    }

    handler := func(flowSetID uint16, flowSetData []byte) (FlowSet, error) {
        switch {
        case flowSetID == flowSetIDTemplateIPFix:
            fs, err := parseIPFixTemplateFlowSet(flowSetData)
            if err == nil {
                for _, template := range fs.Templates {
                    templates.Add(sourceAddr.String(), template.TemplateID, &template)
                }
            }
            return fs, err
        case flowSetID == flowSetIDOptionsIPFix:
            return parseIPFixOptionsTemplateFlowSet(flowSetData)
        case flowSetID >= dataFlowSetMinID:
            template := templates.Get(flowSetID)
            if template != nil {
                return parseIPFixDataFlowSet(flowSetData, flowSetID, template)
            }
            return nil, fmt.Errorf("template not found for FlowSet ID %d (source: %s)", flowSetID, sourceAddr.String())
        default:
            return nil, fmt.Errorf("unknown FlowSet ID: %d", flowSetID)
        }
    }

    flowSets, err := parseFlowSets(data, ipfixHeaderLen, handler)
    if err != nil {
        return nil, err
    }
    packet.FlowSets = append(packet.FlowSets, flowSets...)
    return packet, nil
}

func parseNetFlowV9Header(data []byte) NetFlowV9Header {
	return NetFlowV9Header{
		Version:   binary.BigEndian.Uint16(data[0:2]),
		Count:     binary.BigEndian.Uint16(data[2:4]),
		SysUptime: binary.BigEndian.Uint32(data[4:8]),
		UnixSec:   binary.BigEndian.Uint32(data[8:12]),
		Sequence:  binary.BigEndian.Uint32(data[12:16]),
		SourceID:  binary.BigEndian.Uint32(data[16:20]),
	}
}

func parseIPFixHeader(data []byte) IPFixHeader {
	return IPFixHeader{
		Version:             binary.BigEndian.Uint16(data[0:2]),
		Length:              binary.BigEndian.Uint16(data[2:4]),
		ExportTime:          binary.BigEndian.Uint32(data[4:8]),
		Sequence:            binary.BigEndian.Uint32(data[8:12]),
		ObservationDomainID: binary.BigEndian.Uint32(data[12:16]),
	}
}

func parseTemplateFlowSet(data []byte) (*TemplateFlowSet, error) {
	flowSet := &TemplateFlowSet{
		ID:     binary.BigEndian.Uint16(data[0:2]),
		Length: binary.BigEndian.Uint16(data[2:4]),
	}

	currentOffset := 4
	for currentOffset+4 <= len(data) && currentOffset+4 <= int(flowSet.Length) {
		templateID := binary.BigEndian.Uint16(data[currentOffset : currentOffset+2])
		fieldCount := binary.BigEndian.Uint16(data[currentOffset+2 : currentOffset+4])

		record := TemplateRecord{
			TemplateID: templateID,
			FieldCount: fieldCount,
			Fields:     make([]FieldSpecifier, fieldCount),
		}

		currentOffset += 4
		fieldsParsed := 0

		for fieldsParsed < int(fieldCount) && currentOffset+4 <= len(data) {
			record.Fields[fieldsParsed] = FieldSpecifier{
				Type:   binary.BigEndian.Uint16(data[currentOffset : currentOffset+2]),
				Length: binary.BigEndian.Uint16(data[currentOffset+2 : currentOffset+4]),
			}
			currentOffset += 4
			fieldsParsed++
		}

		flowSet.Templates = append(flowSet.Templates, record)
	}

	return flowSet, nil
}

func parseOptionsTemplateFlowSet(data []byte) (*OptionsTemplateFlowSet, error) {
	flowSet := &OptionsTemplateFlowSet{
		ID:     binary.BigEndian.Uint16(data[0:2]),
		Length: binary.BigEndian.Uint16(data[2:4]),
	}

	currentOffset := 4
	for currentOffset+6 <= len(data) && currentOffset+6 <= int(flowSet.Length) {
		templateID := binary.BigEndian.Uint16(data[currentOffset : currentOffset+2])
		scopeFieldCount := binary.BigEndian.Uint16(data[currentOffset+2 : currentOffset+4])
		optionFieldCount := binary.BigEndian.Uint16(data[currentOffset+4 : currentOffset+6])

		record := OptionsTemplateRecord{
			TemplateID:       templateID,
			ScopeFieldCount:  scopeFieldCount,
			OptionFieldCount: optionFieldCount,
			Fields:           make([]FieldSpecifier, scopeFieldCount+optionFieldCount),
		}

		currentOffset += 6
		fieldsParsed := 0

		totalFields := int(scopeFieldCount + optionFieldCount)
		for fieldsParsed < totalFields && currentOffset+4 <= len(data) {
			record.Fields[fieldsParsed] = FieldSpecifier{
				Type:   binary.BigEndian.Uint16(data[currentOffset : currentOffset+2]),
				Length: binary.BigEndian.Uint16(data[currentOffset+2 : currentOffset+4]),
			}
			currentOffset += 4
			fieldsParsed++
		}

		flowSet.Templates = append(flowSet.Templates, record)
	}

	return flowSet, nil
}

func parseDataFlowSet(data []byte, flowSetID uint16, template *TemplateRecord) (*DataFlowSet, error) {
	flowSet := &DataFlowSet{
		ID:      flowSetID,
		Length:  binary.BigEndian.Uint16(data[2:4]),
		Records: make([]DataRecord, 0),
	}

	dataOffset := 4
	for dataOffset < len(data) {
		record := DataRecord{
			Fields: make(map[uint16]FieldValue),
		}

		recordStart := dataOffset
		for _, field := range template.Fields {
			if dataOffset+int(field.Length) > len(data) {
				return flowSet, nil
			}

			fieldData := data[dataOffset : dataOffset+int(field.Length)]
			fieldValue := FieldValue{
				Type:  field.Type,
				Bytes: fieldData,
				Value: ParseFieldValue(field.Type, fieldData, field.Length),
			}

			record.Fields[field.Type] = fieldValue
			dataOffset += int(field.Length)
		}

		recordLength := dataOffset - recordStart
		padding := calculatePadding(recordLength)
		if dataOffset+padding <= len(data) {
			dataOffset += padding
		}

		flowSet.Records = append(flowSet.Records, record)
	}

	return flowSet, nil
}

func parseIPFixTemplateFlowSet(data []byte) (*TemplateFlowSet, error) {
	return parseTemplateFlowSet(data)
}

func parseIPFixOptionsTemplateFlowSet(data []byte) (*OptionsTemplateFlowSet, error) {
	return parseOptionsTemplateFlowSet(data)
}

func parseIPFixDataFlowSet(data []byte, flowSetID uint16, template *TemplateRecord) (*DataFlowSet, error) {
	return parseDataFlowSet(data, flowSetID, template)
}

func calculatePadding(length int) int {
    return (padAlignment - (length % padAlignment)) % padAlignment
}

func bytesToUint64(data []byte) uint64 {
    var value uint64
    for _, b := range data {
        value = value<<byteShiftBits | uint64(b)
    }
    return value
}
