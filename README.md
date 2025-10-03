# FlowSift

Go библиотека для парсинга NetFlow v9 и IPFix пакетов

## Возможности

* Поддержка NetFlow v9 и IPFix
* Автоматическое кэширование шаблонов
* Парсинг всех типов полей
* Потокобезопасность

## Установка

```bash
go get github.com/RKviZitNT/flowsift
```

## Структура пакета

```go
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
```

## Основные методы

```go
// Создание парсера
parser := flowsift.NewParser()

// Парсинг пакета
packet, err := parcer.Parce(data, sourceIP)

// Работа с полями
fieldName             := flowsift.GetFieldName(field.Type)                      // ANY FIELD
formattedValue        := flowsift.FormatFieldValue(fieldType, fieldValue.Value) // ANY FIELD
flowVersionName       := flowsift.GetFlowVersionName(packet.Version)            // Packet.Version
protocolName          := flowsift.GetProtocolName(fieldValue.Value)             // PROTOCOL
serviceName           := flowsift.GetServiceName(fieldValue.Value)              // L4_SRC_PORT, L4_DST_PORT
samplingAlgorithmName := flowsift.GetSamplingAlgorithmName(fieldValue.Value)    // SAMPLING_ALGORITHM
ipVersionName         := flowsift.GetIPVersionName(fieldValue.Value)            // IPV4_SRC_ADDR, IPV6_SRC_ADDR ...
domainName            := flowsift.GetDomainName(ipAddr)                         // IPV4_SRC_ADDR, IPV6_SRC_ADDR ...
```

## Лиценция

[MIT License](LICENSE)

## Ссылки

* [NetFlow v9 Specification (RFC 3954)](https://datatracker.ietf.org/doc/html/rfc3954)
* [IPFix Specification (RFC 7011)](https://datatracker.ietf.org/doc/html/rfc7011)