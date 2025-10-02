package flowsift

type NetFlowV9Header struct {
	Version   uint16
	Count     uint16
	SysUptime uint32
	UnixSec   uint32
	Sequence  uint32
	SourceID  uint32
}

type IPFixHeader struct {
	Version             uint16
	Length              uint16
	ExportTime          uint32
	Sequence            uint32
	ObservationDomainID uint32
}
