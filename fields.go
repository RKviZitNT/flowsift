package flowsift

import (
	"encoding/binary"
	"fmt"
)

// Parses the value of a field based on its type
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
		if length <= 8 {
			return bytesToUint64(data)
		}
		return data
	}
	return nil
}

// Returns the name of a field by its type
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

		// Additional standard IPFIX fields
		127: "observationPointId",
		128: "selectorId",
		129: "informationElementId",
		130: "selectorAlgorithm",
		131: "samplingPacketInterval",
		132: "samplingPacketSpace",
		133: "samplingTimeInterval",
		134: "samplingTimeSpace",
		135: "samplingSize",
		136: "samplingPopulation",
		137: "samplingProbability",
		138: "dataLinkFrameSize",
		139: "ipHeaderPacketSection",
		140: "ipPayloadPacketSection",
		141: "dataLinkFrameSection",
		142: "mplsLabelStackSection",
		143: "mplsPayloadPacketSection",
		144: "selectorIdTotalPktsObserved",
		145: "selectorIdTotalPktsSelected",
		146: "absoluteError",
		147: "relativeError",
		148: "observationTimeSeconds",
		149: "observationTimeMilliseconds",
		150: "observationTimeMicroseconds",
		151: "observationTimeNanoseconds",
		152: "flowStartSeconds",
		153: "flowEndSeconds",
		154: "flowStartMilliseconds",
		155: "flowEndMilliseconds",
		156: "flowStartMicroseconds",
		157: "flowEndMicroseconds",
		158: "flowStartNanoseconds",
		159: "flowEndNanoseconds",
		160: "flowStartDeltaMicroseconds",
		161: "flowEndDeltaMicroseconds",
		162: "systemInitTimeMilliseconds",
		163: "flowDurationMilliseconds",
		164: "flowDurationMicroseconds",
		165: "observedFlowTotalCount",
		166: "ignoredPacketTotalCount",
		167: "ignoredOctetTotalCount",
		168: "notSentFlowTotalCount",
		169: "notSentPacketTotalCount",
		170: "notSentOctetTotalCount",
		171: "flowKeyIndicator",
		172: "flowSelectorAlgorithm",
		173: "flowSelectedOctetDeltaCount",
		174: "flowSelectedPacketDeltaCount",
		175: "flowSelectedFlowDeltaCount",
		176: "selectorIdTotalFlowsObserved",
		177: "selectorIdTotalFlowsSelected",
		178: "samplingFlowInterval",
		179: "samplingFlowSpacing",
		180: "flowSamplingTimeInterval",
		181: "flowSamplingTimeSpacing",
		182: "hashFlowDomain",
		183: "transportOctetDeltaCount",
		184: "transportPacketDeltaCount",
		185: "originalExporterIPv4Address",
		186: "originalExporterIPv6Address",
		187: "originalObservationDomainId",
		188: "intermediateProcessId",
		189: "ignoredDataRecordTotalCount",
		190: "dataLinkFrameType",
		191: "sectionOffset",
		192: "sectionExportedOctets",
		193: "dot1qServiceInstanceTag",
		194: "dot1qServiceInstanceId",
		195: "dot1qServiceInstancePriority",
		196: "dot1qCustomerSourceMacAddress",
		197: "dot1qCustomerDestinationMacAddress",

		// Routing Information Fields
		200: "bgpNextAdjacentAsNumber",
		201: "bgpPrevAdjacentAsNumber",
		202: "exporterIPv4Address",
		203: "exporterIPv6Address",
		204: "droppedOctetDeltaCount",
		205: "droppedPacketDeltaCount",
		206: "droppedOctetTotalCount",
		207: "droppedPacketTotalCount",
		208: "flowEndReason",
		209: "commonPropertiesId",
		210: "observationPointId2",
		211: "lineCardId",
		212: "portId",
		213: "meteringProcessId",
		214: "exportingProcessId",
		215: "templateId",
		216: "wlanChannelId",
		217: "wlanSSID",
		218: "flowId",
		219: "observationDomainId",
		220: "flowStartSeconds",
		221: "flowEndSeconds",
		222: "flowStartMilliseconds",
		223: "flowEndMilliseconds",
		224: "flowStartMicroseconds",
		225: "flowEndMicroseconds",
		226: "flowStartNanoseconds",
		227: "flowEndNanoseconds",
		228: "flowStartDeltaMicroseconds",
		229: "flowEndDeltaMicroseconds",
		230: "systemInitTimeMilliseconds",
		231: "flowDurationMilliseconds",
		232: "flowDurationMicroseconds",
		233: "flowDirection",

		// Process information fields
		234: "interfaceName",
		235: "interfaceDescription",
		236: "samplerName",
		237: "octetTotalCount",
		238: "packetTotalCount",
		239: "flagsAndSamplerId",
		240: "fragmentOffset",
		241: "forwardingStatus",
		242: "mplsVpnRouteDistinguisher",

		// Additional fields
		243: "mplsTopLabelPrefixLength",
		244: "srcTrafficIndex",
		245: "dstTrafficIndex",
		246: "applicationDescription",
		247: "applicationId",
		248: "applicationName",
		249: "postipDiffServCodePoint",
		250: "replicationFactor",
		251: "layer2packetSectionOffset",
		252: "layer2packetSectionSize",
		253: "layer2packetSectionData",
		256: "bgpNextHopIPv4Address",
		257: "bgpNextHopIPv6Address",
		258: "lineCardId",
		259: "portId",
		260: "meteringProcessId",
		261: "exportingProcessId",
		262: "templateId",
		263: "wlanChannelId",
		264: "wlanSSID",
		265: "flowId",
		266: "observationDomainId",
		267: "flowStartSeconds",
		268: "flowEndSeconds",
		269: "flowStartMilliseconds",
		270: "flowEndMilliseconds",
		271: "flowStartMicroseconds",
		272: "flowEndMicroseconds",
		273: "flowStartNanoseconds",
		274: "flowEndNanoseconds",
		275: "flowStartDeltaMicroseconds",
		276: "flowEndDeltaMicroseconds",
		277: "systemInitTimeMilliseconds",
		278: "flowDurationMilliseconds",
		279: "flowDurationMicroseconds",
		280: "flowDirection",
		281: "interfaceName",
		282: "interfaceDescription",
		283: "samplerName",
		284: "octetTotalCount",
		285: "packetTotalCount",
		286: "flagsAndSamplerId",
		287: "fragmentOffset",
		288: "forwardingStatus",
		289: "mplsVpnRouteDistinguisher",
		290: "mplsTopLabelPrefixLength",
		291: "srcTrafficIndex",
		292: "dstTrafficIndex",
		293: "applicationDescription",

		// Enterprise-specific and additional fields
		294: "applicationId",
		295: "applicationName",
		296: "postipDiffServCodePoint",
		297: "replicationFactor",
		298: "layer2packetSectionOffset",
		299: "layer2packetSectionSize",
		300: "layer2packetSectionData",
		301: "bgpNextHopIPv4Address",
		302: "bgpNextHopIPv6Address",
		303: "entropy",
		304: "flowId",
		305: "flowDirection",
		306: "p2pTechnology",
		307: "tunnelTechnology",
		308: "encryptedTechnology",
		309: "basicList",
		310: "subTemplateList",
		311: "subTemplateMultiList",
		312: "bgpValidityState",
		313: "IPSecSPI",
		314: "greKey",
		315: "natType",
		316: "initiatorPackets",
		317: "responderPackets",
		318: "observationDomainName",
		319: "selectionSequenceId",
		320: "selectorId",
		321: "informationElementId",
		322: "selectorAlgorithm",
		323: "samplingPacketInterval",
		324: "samplingPacketSpace",
		325: "samplingTimeInterval",

		// Additional modern fields
		326: "samplingTimeSpace",
		327: "samplingSize",
		328: "samplingPopulation",
		329: "samplingProbability",
		330: "dataLinkFrameSize",
		331: "ipHeaderPacketSection",
		332: "ipPayloadPacketSection",
		333: "dataLinkFrameSection",
		334: "mplsLabelStackSection",
		335: "mplsPayloadPacketSection",
		336: "selectorIdTotalPktsObserved",
		337: "selectorIdTotalPktsSelected",
		338: "absoluteError",
		339: "relativeError",
		340: "observationTimeSeconds",
		341: "observationTimeMilliseconds",
		342: "observationTimeMicroseconds",
		343: "observationTimeNanoseconds",
		344: "digestHashValue",
		345: "hashIPPayloadOffset",
		346: "hashIPPayloadSize",
		347: "hashOutputRangeMin",
		348: "hashOutputRangeMax",
		349: "hashSelectedRangeMin",
		350: "hashSelectedRangeMax",
		351: "hashDigestOutput",
		352: "hashInitialiserValue",
		353: "selectorName",
		354: "upperCILimit",
		355: "lowerCILimit",
		356: "confidenceLevel",
		357: "informationElementDataType",
		358: "informationElementDescription",
		359: "informationElementName",
		360: "informationElementRangeBegin",
		361: "informationElementRangeEnd",
		362: "informationElementSemantics",
		363: "informationElementUnits",
		364: "privateEnterpriseNumber",
		365: "virtualStationInterfaceId",
		366: "virtualStationInterfaceName",
		367: "virtualStationUUID",
		368: "virtualStationName",
		369: "layer2SegmentId",
		370: "layer2OctetDeltaCount",
		371: "layer2OctetTotalCount",
		372: "ingressUnicastPacketTotalCount",
		373: "ingressMulticastPacketTotalCount",
		374: "ingressBroadcastPacketTotalCount",
		375: "egressUnicastPacketTotalCount",
		376: "egressMulticastPacketTotalCount",
		377: "egressBroadcastPacketTotalCount",
		378: "monitoringIntervalStartMilliSeconds",
		379: "monitoringIntervalEndMilliSeconds",
		380: "portRangeStart",
		381: "portRangeEnd",
		382: "portRangeStepSize",
		383: "portRangeNumPorts",
		384: "staMacAddress",
		385: "staIPv4Address",
		386: "wtpMacAddress",
		387: "ingressInterfaceType",
		388: "egressInterfaceType",
		389: "rtpSequenceNumber",
		390: "userName",
		391: "applicationCategoryName",
		392: "applicationSubCategoryName",
		393: "applicationGroupName",
		394: "originalFlowsPresent",
		395: "originalFlowsInitiated",
		396: "originalFlowsCompleted",
		397: "distinctCountOfSourceIPAddress",
		398: "distinctCountOfDestinationIPAddress",
		399: "distinctCountOfSourceIPv4Address",
		400: "distinctCountOfDestinationIPv4Address",
		401: "distinctCountOfSourceIPv6Address",
		402: "distinctCountOfDestinationIPv6Address",
		403: "valueDistributionMethod",
		404: "rfc3550JitterMilliseconds",
		405: "rfc3550JitterMicroseconds",
		406: "rfc3550JitterNanoseconds",
		407: "dot1qDEI",
		408: "dot1qCustomerDEI",
		409: "flowSelectorAlgorithm",
		410: "flowSelectedOctetDeltaCount",
		411: "flowSelectedPacketDeltaCount",
		412: "flowSelectedFlowDeltaCount",
		413: "selectorIdTotalFlowsObserved",
		414: "selectorIdTotalFlowsSelected",
		415: "samplingFlowInterval",
		416: "samplingFlowSpacing",
		417: "flowSamplingTimeInterval",
		418: "flowSamplingTimeSpacing",
		419: "hashFlowDomain",
		420: "transportOctetDeltaCount",
		421: "transportPacketDeltaCount",
		422: "originalExporterIPv4Address",
		423: "originalExporterIPv6Address",
		424: "originalObservationDomainId",
		425: "intermediateProcessId",
		426: "ignoredDataRecordTotalCount",
		427: "dataLinkFrameType",
		428: "sectionOffset",
		429: "sectionExportedOctets",
		430: "dot1qServiceInstanceTag",
		431: "dot1qServiceInstanceId",
		432: "dot1qServiceInstancePriority",
		433: "dot1qCustomerSourceMacAddress",
		434: "dot1qCustomerDestinationMacAddress",
		435: "dot1qCustomerVlanId",
		436: "dot1qVlanId",
		437: "postLayer2OctetDeltaCount",
		438: "postMCastLayer2OctetDeltaCount",
		439: "postLayer2OctetTotalCount",
		440: "postMCastLayer2OctetTotalCount",
		441: "minimumLayer2TotalLength",
		442: "maximumLayer2TotalLength",
		443: "droppedLayer2OctetDeltaCount",
		444: "droppedLayer2OctetTotalCount",
		445: "ignoredLayer2OctetTotalCount",
		446: "notSentLayer2OctetTotalCount",
		447: "layer2OctetDeltaSumOfSquares",
		448: "layer2OctetTotalSumOfSquares",
		449: "layer2FrameDeltaCount",
		450: "layer2FrameTotalCount",
		451: "pseudoWireDestinationIPv4Address",
		452: "pseudoWireDestinationIPv6Address",
		453: "pseudoWireId",
		454: "pseudoWireType",
		455: "pseudoWireControlWord",
	}

	if name, exists := fieldNames[fieldType]; exists {
		return name
	}
	return fmt.Sprintf("UNKNOWN_%d", fieldType)
}

// Returns the protocol name
func GetProtocolName(protocol uint8) string {
	protocols := map[uint8]string{
		0:   "HOPOPT",
		1:   "ICMP",
		2:   "IGMP",
		3:   "GGP",
		4:   "IPv4 (IP-in-IP)",
		5:   "ST",
		6:   "TCP",
		7:   "CBT",
		8:   "EGP",
		9:   "IGP",
		10:  "BBN-RCC-MON",
		11:  "NVP-II",
		12:  "PUP",
		13:  "ARGUS (deprecated)",
		14:  "EMCON",
		15:  "XNET",
		16:  "CHAOS",
		17:  "UDP",
		18:  "MUX",
		19:  "DCN-MEAS",
		20:  "HMP",
		21:  "PRM",
		22:  "XNS-IDP",
		23:  "TRUNK-1",
		24:  "TRUNK-2",
		25:  "LEAF-1",
		26:  "LEAF-2",
		27:  "RDP",
		28:  "IRTP",
		29:  "ISO-TP4",
		30:  "NETBLT",
		31:  "MFE-NSP",
		32:  "MERIT-INP",
		33:  "DCCP",
		34:  "3PC",
		35:  "IDPR",
		36:  "XTP",
		37:  "DDP",
		38:  "IDPR-CMTP",
		39:  "TP++",
		40:  "IL",
		41:  "IPv6",
		42:  "SDRP",
		43:  "IPv6-Route",
		44:  "IPv6-Frag",
		45:  "IDRP",
		46:  "RSVP",
		47:  "GRE",
		48:  "DSR",
		49:  "BNA",
		50:  "ESP",
		51:  "AH",
		52:  "I-NLSP",
		53:  "SWIPE (deprecated)",
		54:  "NARP",
		55:  "Min-IPv4",
		56:  "TLSP",
		57:  "SKIP",
		58:  "IPv6-ICMP",
		59:  "IPv6-NoNxt",
		60:  "IPv6-Opts",
		61:  "(any host internal protocol)",
		62:  "CFTP",
		63:  "(any local network)",
		64:  "SAT-EXPAK",
		65:  "KRYPTOLAN",
		66:  "RVD",
		67:  "IPPC",
		68:  "(any distributed file system)",
		69:  "SAT-MON",
		70:  "VISA",
		71:  "IPCV",
		72:  "CPNX",
		73:  "CPHB",
		74:  "WSN",
		75:  "PVP",
		76:  "BR-SAT-MON",
		77:  "SUN-ND",
		78:  "WB-MON",
		79:  "WB-EXPAK",
		80:  "ISO-IP",
		81:  "VMTP",
		82:  "SECURE-VMTP",
		83:  "VINES",
		84:  "IPTM",
		85:  "NSFNET-IGP",
		86:  "DGP",
		87:  "TCF",
		88:  "EIGRP",
		89:  "OSPF",
		90:  "Sprite-RPC",
		91:  "LARP",
		92:  "MTP",
		93:  "AX.25",
		94:  "IPIP",
		95:  "MICP (deprecated)",
		96:  "SCC-SP",
		97:  "ETHERIP",
		98:  "ENCAP",
		99:  "(private encryption scheme)",
		100: "GMTP",
		101: "IFMP",
		102: "PNNI",
		103: "PIM",
		104: "ARIS",
		105: "SCPS",
		106: "QNX",
		107: "A/N",
		108: "IPComp",
		109: "SNP",
		110: "Compaq-Peer",
		111: "IPX-in-IP",
		112: "VRRP",
		113: "PGM",
		114: "(any 0-hop protocol)",
		115: "L2TP",
		116: "DDX",
		117: "IATP",
		118: "STP",
		119: "SRP",
		120: "UTI",
		121: "SMP",
		122: "SM (deprecated)",
		123: "PTP",
		124: "ISIS over IPv4",
		125: "FIRE",
		126: "CRTP",
		127: "CRUDP",
		128: "SSCOPMCE",
		129: "IPLT",
		130: "SPS",
		131: "PIPE",
		132: "SCTP",
		133: "FC",
		134: "RSVP-E2E-IGNORE",
		135: "Mobility Header",
		136: "UDPLite",
		137: "MPLS-in-IP",
		138: "manet",
		139: "HIP",
		140: "Shim6",
		141: "WESP",
		142: "ROHC",
		143: "Ethernet",
		144: "AGGFRAG",
		145: "NSH",
		146: "Homa",
		147: "BIT-EMU",
	}
	if name, exists := protocols[protocol]; exists {
		return name
	}
	return "Unknown"
}

// Returns the service name by port
func GetServiceName(port uint16) string {
	services := map[uint16]string{
		20:    "FTP-DATA",
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		67:    "DHCP-Server",
		68:    "DHCP-Client",
		69:    "TFTP",
		80:    "HTTP",
		110:   "POP3",
		119:   "NNTP",
		123:   "NTP",
		135:   "MS RPC",
		137:   "NetBIOS-Name",
		138:   "NetBIOS-Datagram",
		139:   "NetBIOS-Session",
		143:   "IMAP",
		161:   "SNMP",
		162:   "SNMP-Trap",
		179:   "BGP",
		194:   "IRC",
		389:   "LDAP",
		443:   "HTTPS",
		445:   "SMB (Windows Sharing)",
		465:   "SMTPS",
		500:   "ISAKMP (IPsec VPN)",
		514:   "Syslog",
		520:   "RIP",
		587:   "SMTP-Submission",
		631:   "IPP (Printing)",
		636:   "LDAPS",
		873:   "rsync",
		990:   "FTPS",
		993:   "IMAPS",
		995:   "POP3S",
		1080:  "SOCKS Proxy",
		1194:  "OpenVPN",
		1234:  "VLC/Streaming",
		1433:  "MSSQL",
		1434:  "MSSQL Monitor",
		1521:  "Oracle DB",
		1701:  "L2TP",
		1723:  "PPTP",
		1812:  "RADIUS (Auth)",
		1813:  "RADIUS (Acct)",
		1883:  "MQTT (IoT)",
		1900:  "SSDP (UPnP)",
		2049:  "NFS",
		2082:  "cPanel",
		2083:  "cPanel SSL",
		2181:  "Zookeeper",
		2222:  "DirectAdmin",
		2375:  "Docker API (Unsecured)",
		2376:  "Docker API (TLS)",
		2483:  "Oracle DB (TCPS)",
		2484:  "Oracle DB (TCPS)",
		27017: "MongoDB",
		3000:  "Grafana / Dev Apps",
		3128:  "Squid Proxy",
		3306:  "MySQL",
		3389:  "RDP (Remote Desktop)",
		3690:  "SVN",
		4369:  "Erlang Port Mapper",
		4444:  "Metasploit / Remote Shell",
		4567:  "Galera (MySQL Cluster)",
		5000:  "Flask / Dev API",
		5432:  "PostgreSQL",
		5672:  "AMQP (RabbitMQ)",
		5900:  "VNC",
		5984:  "CouchDB",
		6379:  "Redis",
		7001:  "WebLogic",
		7071:  "Zimbra Admin",
		7474:  "Neo4j",
		8000:  "Dev HTTP",
		8080:  "HTTP-Alt / Proxy",
		8081:  "HTTP-Alt / Jenkins",
		8443:  "HTTPS-Alt",
		8888:  "Alt UI / Proxy",
		9000:  "SonarQube / PHP-FPM",
		9090:  "Prometheus / Web UI",
		9200:  "Elasticsearch",
		9300:  "Elasticsearch Transport",
		9418:  "Git",
		9999:  "App Debug / Custom",
	}
	if name, exists := services[port]; exists {
		return name
	}
	return "Unknown"
}

// Returns the type of sampling algorithm
func GetSamplingAlgorithmName(algorithm uint8) string {
	samplingAlgorithms := map[uint8]string{
		0:  "Unknown / Not Used",
		1:  "Deterministic",
		2:  "Random",
		3:  "Systematic Count-Based",
		4:  "Systematic Time-Based",
		5:  "Probabilistic",
		6:  "Hash-Based",
		7:  "Uniform",
		8:  "Non-Uniform",
		9:  "Stratified",
		10: "Flow-Based",
		11: "Packet-Based",
	}

	if name, exists := samplingAlgorithms[algorithm]; exists {
		return name
	}
	return "Unknown"
}

// Returns the IP version
func GetIPVersionName(version uint8) string {
	ipVersions := map[uint8]string{
		4: "IPv4",
		6: "IPv6",
	}

	if name, exists := ipVersions[version]; exists {
		return name
	}
	return "Unknown"
}

// Parses TCP flags
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

// Formats the field value for output
func FormatFieldValue(fieldType uint16, value interface{}) string {
	switch v := value.(type) {
	case uint64:
		return fmt.Sprintf("%d", v)
	case uint32:
		return fmt.Sprintf("%d", v)
	case uint16:
		if fieldType == 7 || fieldType == 11 { // Port
			return fmt.Sprintf("%d (%s)", v, GetServiceName(v))
		}
		return fmt.Sprintf("%d", v)
	case uint8:
		if fieldType == 4 { // Protocol
			return fmt.Sprintf("%d (%s)", v, GetProtocolName(v))
		}
		if fieldType == 6 { // TCP flags
			return fmt.Sprintf("0x%02x (%s)", v, ParseTCPFlags(v))
		}
		if fieldType == 35 { // Sampling algorithm
			return fmt.Sprintf("%d (%s)", v, GetSamplingAlgorithmName(v))
		}
		if fieldType == 60 { // IP version
			return fmt.Sprintf("%d (%s)", v, GetIPVersionName(v))
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
