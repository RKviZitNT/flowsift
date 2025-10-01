package flowsift

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// ParseNetFlowV9 разбирает NetFlow v9 пакет
func ParseNetFlowV9(data []byte, sourceAddr net.IP, templates *TemplateCache) (*Packet, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("NetFlow v9 packet too short: %d bytes", len(data))
	}

	header := parseNetFlowV9Header(data[:20])

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

	offset := 20
	for offset+4 <= len(data) {
		flowSetID := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])

		if length < 4 {
			return nil, fmt.Errorf("invalid FlowSet length: %d", length)
		}

		if offset+int(length) > len(data) {
			return nil, fmt.Errorf("FlowSet length %d exceeds packet size", length)
		}

		flowSetData := data[offset : offset+int(length)]

		var flowSet FlowSet
		var err error

		switch {
		case flowSetID == 0:
			flowSet, err = parseTemplateFlowSet(flowSetData)
			if err == nil {
				// Добавляем шаблоны в кэш
				if templateFlowSet, ok := flowSet.(*TemplateFlowSet); ok {
					for _, template := range templateFlowSet.Templates {
						templates.Add(sourceAddr.String(), template.TemplateID, &template)
					}
				}
			}
		case flowSetID == 1:
			flowSet, err = parseOptionsTemplateFlowSet(flowSetData)
		case flowSetID >= 256:
			template := templates.Get(flowSetID)
			if template != nil {
				flowSet, err = parseDataFlowSet(flowSetData, flowSetID, template)
			} else {
				// Шаблон не найден, создаем базовый DataFlowSet без парсинга записей
				flowSet = &DataFlowSet{
					ID:     flowSetID,
					Length: length,
				}
			}
		default:
			flowSet = &DataFlowSet{
				ID:     flowSetID,
				Length: length,
			}
		}

		if err != nil {
			return nil, err
		}

		if flowSet != nil {
			packet.FlowSets = append(packet.FlowSets, flowSet)
		}

		offset += int(length)
	}

	return packet, nil
}

// ParseIPFix разбирает IPFix пакет
func ParseIPFix(data []byte, sourceAddr net.IP, templates *TemplateCache) (*Packet, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("IPFix packet too short: %d bytes", len(data))
	}

	header := parseIPFixHeader(data[:16])

	packet := &Packet{
		Version:    header.Version,
		Sequence:   header.Sequence,
		SourceID:   header.ObservationDomainID,
		SourceAddr: sourceAddr,
		Timestamp:  time.Unix(int64(header.ExportTime), 0),
		FlowSets:   make([]FlowSet, 0),
	}

	offset := 16
	for offset+4 <= len(data) {
		flowSetID := binary.BigEndian.Uint16(data[offset : offset+2])
		length := binary.BigEndian.Uint16(data[offset+2 : offset+4])

		if length < 4 {
			return nil, fmt.Errorf("invalid FlowSet length: %d", length)
		}

		if offset+int(length) > len(data) {
			return nil, fmt.Errorf("FlowSet length %d exceeds packet size", length)
		}

		flowSetData := data[offset : offset+int(length)]

		var flowSet FlowSet
		var err error

		switch {
		case flowSetID == 2:
			flowSet, err = parseIPFixTemplateFlowSet(flowSetData)
			if err == nil {
				// Добавляем шаблоны в кэш
				if templateFlowSet, ok := flowSet.(*TemplateFlowSet); ok {
					for _, template := range templateFlowSet.Templates {
						templates.Add(sourceAddr.String(), template.TemplateID, &template)
					}
				}
			}
		case flowSetID == 3:
			flowSet, err = parseIPFixOptionsTemplateFlowSet(flowSetData)
		case flowSetID >= 256:
			template := templates.Get(flowSetID)
			if template != nil {
				flowSet, err = parseIPFixDataFlowSet(flowSetData, flowSetID, template)
			} else {
				flowSet = &DataFlowSet{
					ID:     flowSetID,
					Length: length,
				}
			}
		default:
			flowSet = &DataFlowSet{
				ID:     flowSetID,
				Length: length,
			}
		}

		if err != nil {
			return nil, err
		}

		if flowSet != nil {
			packet.FlowSets = append(packet.FlowSets, flowSet)
		}

		offset += int(length)
	}

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
				// Неполная запись, возвращаем что успели распарсить
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

		// Выравнивание
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
	// Аналогично NetFlow v9
	return parseTemplateFlowSet(data)
}

func parseIPFixOptionsTemplateFlowSet(data []byte) (*OptionsTemplateFlowSet, error) {
	// Аналогично NetFlow v9
	return parseOptionsTemplateFlowSet(data)
}

func parseIPFixDataFlowSet(data []byte, flowSetID uint16, template *TemplateRecord) (*DataFlowSet, error) {
	// Аналогично NetFlow v9
	return parseDataFlowSet(data, flowSetID, template)
}

// calculatePadding вычисляет выравнивание
func calculatePadding(length int) int {
	return (4 - (length % 4)) % 4
}

// bytesToUint64 преобразует байты в uint64
func bytesToUint64(data []byte) uint64 {
	var value uint64
	for _, b := range data {
		value = value<<8 | uint64(b)
	}
	return value
}
