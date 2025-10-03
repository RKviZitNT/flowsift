package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/RKviZitNT/flowsift"
)

func main() {
	parser := flowsift.NewParser(flowsift.Config{
		TemplateTimeout: 30 * time.Minute,
	})

	addr, err := net.ResolveUDPAddr("udp", ":2055")
	if err != nil {
		log.Fatal("Error resolving UDP address:", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal("Error listening on UDP:", err)
	}
	defer conn.Close()

	fmt.Println("NetFlow/IPFix Collector started on port 2055...")
	fmt.Printf("Loaded templates: %d\n", len(parser.GetTemplates()))

	buffer := make([]byte, 8192)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error reading UDP: %v", err)
			continue
		}

		handlePacket(parser, buffer[:n], clientAddr.IP)
	}
}

func handlePacket(parser *flowsift.Parser, data []byte, sourceAddr net.IP) {
	packet, err := parser.Parse(data, sourceAddr)
	if err != nil {
		log.Printf("Error parsing packet from %s: %v", sourceAddr, err)
		return
	}

	fmt.Printf("\n=== Received %s packet from %s at %s ===\n", flowsift.GetFlowVersionName(packet.Version), sourceAddr, time.Now().Format("15:04:05.000"))

	fmt.Printf("Packet Info:\n")
	fmt.Printf("  Version: %d\n", packet.Version)
	fmt.Printf("  Count: %d\n", packet.Count)
	fmt.Printf("  SysUptime: %d\n", packet.SysUptime)
	fmt.Printf("  UnixSec: %d\n", packet.UnixSec)
	fmt.Printf("  Sequence: %d\n", packet.Sequence)
	fmt.Printf("  SourceID: %d\n", packet.SourceID)
	fmt.Printf("  FlowSets: %d\n", len(packet.FlowSets))

	templateCount := 0
	dataCount := 0

	for _, flowSet := range packet.FlowSets {
		switch fs := flowSet.(type) {
		case *flowsift.TemplateFlowSet:
			templateCount++
			fmt.Printf("  Template FlowSet (ID=%d): %d templates\n", fs.ID, len(fs.Templates))
			for _, template := range fs.Templates {
				fmt.Printf("    Template ID=%d with %d fields:\n", template.TemplateID, template.FieldCount)
				for i, field := range template.Fields {
					fieldName := flowsift.GetFieldName(field.Type)
					fmt.Printf("      Field %d: %s (Type=%d, Length=%d)\n", i+1, fieldName, field.Type, field.Length)
				}
			}
		case *flowsift.DataFlowSet:
			dataCount++
			fmt.Printf("  Data FlowSet (Template ID=%d): %d records\n", fs.ID, len(fs.Records))
			for i, record := range fs.Records {
				fmt.Printf("    Record %d:\n", i+1)
				for fieldType, fieldValue := range record.Fields {
					fieldName := flowsift.GetFieldName(fieldType)
					formattedValue := flowsift.FormatFieldValue(fieldType, fieldValue.Value)
					fmt.Printf("      %s: %s\n", fieldName, formattedValue)
				}
			}
		case *flowsift.OptionsTemplateFlowSet:
			fmt.Printf("  Options Template FlowSet (ID=%d): %d templates\n", fs.ID, len(fs.Templates))
		}
	}

	fmt.Printf("  Processed: %d Template FlowSets, %d Data FlowSets\n", templateCount, dataCount)
	fmt.Printf("  Total templates in memory: %d\n", len(parser.GetTemplates()))
	fmt.Printf("=== End of packet ===\n")
}
