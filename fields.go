package flowsift

import (
	"encoding/binary"
	"fmt"
)

// ParseFieldValue парсит значение поля на основе его типа
func ParseFieldValue(fieldType uint16, data []byte, length uint16) interface{} {
	switch fieldType {
	case 1, 2, 3, 23, 24: // IN_BYTES, IN_PKTS, FLOWS, OUT_BYTES, OUT_PKTS
		return bytesToUint64(data)
	case 4: // PROTOCOL
		if len(data) >= 1 {
			return data[0]
		}
	case 5: // SRC_TOS
		if len(data) >= 1 {
			return data[0]
		}
	case 6: // TCP_FLAGS
		if len(data) >= 1 {
			return data[0]
		}
	case 7, 11: // L4_SRC_PORT, L4_DST_PORT
		if len(data) >= 2 {
			return binary.BigEndian.Uint16(data)
		}
	case 8, 12, 15: // IPV4_SRC_ADDR, IPV4_DST_ADDR, IPV4_NEXT_HOP
		return parseIPv4(data)
	case 10, 14, 21, 22, 34: // INPUT_SNMP, OUTPUT_SNMP, LAST_SWITCHED, FIRST_SWITCHED, SAMPLING_INTERVAL
		if len(data) >= 4 {
			return binary.BigEndian.Uint32(data)
		}
	case 16, 17: // SRC_AS, DST_AS
		if len(data) >= 2 {
			return binary.BigEndian.Uint16(data)
		} else if len(data) >= 4 {
			return binary.BigEndian.Uint32(data)
		}
	case 27, 28, 62: // IPV6_SRC_ADDR, IPV6_DST_ADDR, IPV6_NEXT_HOP
		return parseIPv6(data)
	case 31: // IPV6_FLOW_LABEL
		if len(data) >= 4 {
			return binary.BigEndian.Uint32(data) & 0x000FFFFF
		}
	case 32: // ICMP_TYPE
		if len(data) >= 2 {
			return map[string]uint8{"type": data[0], "code": data[1]}
		}
	case 35: // SAMPLING_ALGORITHM
		if len(data) >= 1 {
			return data[0]
		}
	case 56, 57, 80, 81: // SRC_MAC, DST_MAC, IN_DST_MAC, OUT_SRC_MAC
		return parseMAC(data)
	case 58, 59: // SRC_VLAN, DST_VLAN
		if len(data) >= 2 {
			return binary.BigEndian.Uint16(data)
		}
	case 60: // IP_PROTOCOL_VERSION
		if len(data) >= 1 {
			return data[0]
		}
	default:
		// Для неизвестных полей возвращаем сырые данные или преобразуем в число
		if length <= 8 {
			return bytesToUint64(data)
		}
		return data
	}
	return nil
}

// GetFieldName возвращает имя поля по его типу
func GetFieldName(fieldType uint16) string {
	fieldNames := map[uint16]string{
		1:   "IN_BYTES",
		2:   "IN_PKTS",
		3:   "FLOWS",
		4:   "PROTOCOL",
		5:   "SRC_TOS",
		6:   "TCP_FLAGS",
		7:   "L4_SRC_PORT",
		8:   "IPV4_SRC_ADDR",
		9:   "SRC_MASK",
		10:  "INPUT_SNMP",
		11:  "L4_DST_PORT",
		12:  "IPV4_DST_ADDR",
		13:  "DST_MASK",
		14:  "OUTPUT_SNMP",
		15:  "IPV4_NEXT_HOP",
		16:  "SRC_AS",
		17:  "DST_AS",
		18:  "BGP_IPV4_NEXT_HOP",
		19:  "MUL_DST_PKTS",
		20:  "MUL_DST_BYTES",
		21:  "LAST_SWITCHED",
		22:  "FIRST_SWITCHED",
		23:  "OUT_BYTES",
		24:  "OUT_PKTS",
		25:  "MIN_PKT_LNGTH",
		26:  "MAX_PKT_LNGTH",
		27:  "IPV6_SRC_ADDR",
		28:  "IPV6_DST_ADDR",
		29:  "IPV6_SRC_MASK",
		30:  "IPV6_DST_MASK",
		31:  "IPV6_FLOW_LABEL",
		32:  "ICMP_TYPE",
		33:  "MUL_IGMP_TYPE",
		34:  "SAMPLING_INTERVAL",
		35:  "SAMPLING_ALGORITHM",
		36:  "FLOW_ACTIVE_TIMEOUT",
		37:  "FLOW_INACTIVE_TIMEOUT",
		38:  "ENGINE_TYPE",
		39:  "ENGINE_ID",
		40:  "TOTAL_BYTES_EXP",
		41:  "TOTAL_PKTS_EXP",
		42:  "TOTAL_FLOWS_EXP",
		44:  "IPV4_SRC_PREFIX",
		45:  "IPV4_DST_PREFIX",
		46:  "MPLS_TOP_LABEL_TYPE",
		47:  "MPLS_TOP_LABEL_IP",
		48:  "FLOW_SAMPLER_ID",
		49:  "FLOW_SAMPLER_MODE",
		50:  "FLOW_SAMPLER_RANDOM_INTERVAL",
		55:  "DST_TOS",
		56:  "SRC_MAC",
		57:  "DST_MAC",
		58:  "SRC_VLAN",
		59:  "DST_VLAN",
		60:  "IP_PROTOCOL_VERSION",
		61:  "DIRECTION",
		62:  "IPV6_NEXT_HOP",
		63:  "BPG_IPV6_NEXT_HOP",
		64:  "IPV6_OPTION_HEADERS",
		70:  "MPLS_LABEL_1",
		71:  "MPLS_LABEL_2",
		72:  "MPLS_LABEL_3",
		73:  "MPLS_LABEL_4",
		74:  "MPLS_LABEL_5",
		75:  "MPLS_LABEL_6",
		76:  "MPLS_LABEL_7",
		77:  "MPLS_LABEL_8",
		78:  "MPLS_LABEL_9",
		79:  "MPLS_LABEL_10",
		80:  "IN_DST_MAC",
		81:  "OUT_SRC_MAC",
		82:  "IF_NAME",
		83:  "IF_DESC",
		84:  "SAMPLER_NAME",
		85:  "IN_PERMANENT_BYTES",
		86:  "IN_PERMANENT_PKTS",
		88:  "FRAGMENT_OFFSET",
		89:  "FORWARDING_STATUS",
		90:  "MPLS_PAL_RD",
		91:  "MPLS_PREFIX_LEN",
		92:  "SRC_TRAFFIC_INDEX",
		93:  "DST_TRAFFIC_INDEX",
		94:  "APPLICATION_DESCRIPTION",
		95:  "APPLICATION_TAG",
		96:  "APPLICATION_NAME",
		98:  "postipDiffServCodePoint",
		99:  "replication_factor",
		100: "DEPRECATED",
		102: "layer2packetSectionOffset",
		103: "layer2packetSectionSize",
		104: "layer2packetSectionData",
		// IPFix specific fields
		152: "flowStartSeconds",
		153: "flowEndSeconds",
		154: "flowStartMilliseconds",
		155: "flowEndMilliseconds",
		156: "flowStartMicroseconds",
		157: "flowEndMicroseconds",
		158: "flowStartNanoseconds",
		159: "flowEndNanoseconds",
	}

	if name, exists := fieldNames[fieldType]; exists {
		return name
	}
	return fmt.Sprintf("UNKNOWN_%d", fieldType)
}

// GetProtocolName возвращает имя протокола
func GetProtocolName(protocol uint8) string {
	protocols := map[uint8]string{
		1:   "ICMP",
		6:   "TCP",
		17:  "UDP",
		47:  "GRE",
		50:  "ESP",
		51:  "AH",
		58:  "ICMPv6",
		132: "SCTP",
	}
	if name, exists := protocols[protocol]; exists {
		return name
	}
	return "Unknown"
}

// GetServiceName возвращает имя сервиса по порту
func GetServiceName(port uint16) string {
	services := map[uint16]string{
		20:   "FTP-DATA",
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		143:  "IMAP",
		443:  "HTTPS",
		993:  "IMAPS",
		995:  "POP3S",
		3306: "MySQL",
		3389: "RDP",
		5432: "PostgreSQL",
	}
	if name, exists := services[port]; exists {
		return name
	}
	return "Unknown"
}

// ParseTCPFlags парсит TCP флаги
func ParseTCPFlags(flags uint8) string {
	var result string
	if flags&0x01 != 0 {
		result += "FIN "
	}
	if flags&0x02 != 0 {
		result += "SYN "
	}
	if flags&0x04 != 0 {
		result += "RST "
	}
	if flags&0x08 != 0 {
		result += "PSH "
	}
	if flags&0x10 != 0 {
		result += "ACK "
	}
	if flags&0x20 != 0 {
		result += "URG "
	}
	if flags&0x40 != 0 {
		result += "ECE "
	}
	if flags&0x80 != 0 {
		result += "CWR "
	}
	if result == "" {
		return "None"
	}
	return result
}

// FormatFieldValue форматирует значение поля для вывода
func FormatFieldValue(fieldType uint16, value interface{}) string {
	switch v := value.(type) {
	case uint64:
		return fmt.Sprintf("%d", v)
	case uint32:
		return fmt.Sprintf("%d", v)
	case uint16:
		if fieldType == 7 || fieldType == 11 { // Порт
			return fmt.Sprintf("%d (%s)", v, GetServiceName(v))
		}
		return fmt.Sprintf("%d", v)
	case uint8:
		if fieldType == 4 { // Протокол
			return fmt.Sprintf("%d (%s)", v, GetProtocolName(v))
		}
		if fieldType == 6 { // TCP флаги
			return fmt.Sprintf("0x%02x (%s)", v, ParseTCPFlags(v))
		}
		if fieldType == 35 { // Алгоритм сэмплирования
			algo := "Unknown"
			if v == 1 {
				algo = "Deterministic"
			} else if v == 2 {
				algo = "Random"
			}
			return fmt.Sprintf("%d (%s)", v, algo)
		}
		if fieldType == 60 { // Версия IP
			version := "Unknown"
			if v == 4 {
				version = "IPv4"
			} else if v == 6 {
				version = "IPv6"
			}
			return fmt.Sprintf("%d (%s)", v, version)
		}
		return fmt.Sprintf("%d", v)
	case string:
		return v
	case map[string]uint8:
		if fieldType == 32 { // ICMP type/code
			return fmt.Sprintf("type=%d code=%d", v["type"], v["code"])
		}
		return fmt.Sprintf("%v", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func parseIPv4(data []byte) string {
	if len(data) != 4 {
		return fmt.Sprintf("Invalid IPv4 (%d bytes)", len(data))
	}
	return fmt.Sprintf("%d.%d.%d.%d", data[0], data[1], data[2], data[3])
}

func parseIPv6(data []byte) string {
	if len(data) != 16 {
		return fmt.Sprintf("Invalid IPv6 (%d bytes)", len(data))
	}
	return fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
		data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15])
}

func parseMAC(data []byte) string {
	if len(data) != 6 {
		return fmt.Sprintf("Invalid MAC (%d bytes)", len(data))
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		data[0], data[1], data[2], data[3], data[4], data[5])
}
