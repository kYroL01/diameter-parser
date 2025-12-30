package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/fiorix/go-diameter/v4/diam"
	"github.com/fiorix/go-diameter/v4/diam/datatype"
	"github.com/fiorix/go-diameter/v4/diam/dict"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type MessageInfo struct {
	CommandCode      uint32    `json:"command_code"`
	CommandCodeName  string    `json:"command_code_name,omitempty"`
	CommandFlags     uint8     `json:"command_flags"`
	CommandFlagsName string    `json:"command_flags_name,omitempty"`
	ApplicationID    uint32    `json:"application_id"`
	ApplicationName  string    `json:"application_name,omitempty"`
	HopByHopID       uint32    `json:"hop_by_hop_id"`
	EndToEndID       uint32    `json:"end_to_end_id"`
	AVPs             []AVPInfo `json:"avps"`
}

type AVPInfo struct {
	Code     uint32      `json:"code"`
	VendorID uint32      `json:"vendor_id,omitempty"`
	Name     string      `json:"name,omitempty"`
	Data     interface{} `json:"data"`
}

type GroupedData struct {
	AVPs []AVPInfo `json:"avps"`
}

type PLMN struct {
	MCC string `json:"mcc"`
	MNC string `json:"mnc"`
	Hex string `json:"hex"`
}

func main() {
	pcapFile := flag.String("pcap", "", "Path to the PCAP file")
	flag.Parse()

	if *pcapFile == "" {
		log.Fatal("Please provide a PCAP file using -pcap")
	}

	// Load the default dictionary (Base + common apps).
	d := dict.Default

	handle, err := pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatal("Failed to open PCAP file:", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		appLayer := packet.ApplicationLayer()
		if appLayer == nil {
			continue
		}
		payload := appLayer.Payload()
		if len(payload) == 0 {
			continue
		}

		// Use dictionary when reading the message.
		msg, err := diam.ReadMessage(bytes.NewReader(payload), d)
		if err != nil {
			// Not a Diameter message, or incomplete.
			continue
		}

		// Extract message info.
		mi := MessageInfo{
			CommandCode:      msg.Header.CommandCode,
			CommandCodeName:  commandCodeName(msg.Header.CommandCode),
			CommandFlags:     msg.Header.CommandFlags,
			CommandFlagsName: commandFlagsName(msg.Header.CommandFlags),
			ApplicationID:    msg.Header.ApplicationID,
			ApplicationName:  applicationName(msg.Header.ApplicationID),
			HopByHopID:       msg.Header.HopByHopID,
			EndToEndID:       msg.Header.EndToEndID,
		}

		for _, a := range msg.AVP {

			// Lookup AVP name from dictionary.
			name := avpNameFromDict(d, msg.Header.ApplicationID, a.Code, a.VendorID)
			// Convert AVP data to JSON-friendly value.
			var data interface{} = avpToJSONValue(a.Data)

			// If this is a grouped AVP, decode its children.
			if g, ok := a.Data.(datatype.Grouped); ok {
				ga, err := diam.DecodeGrouped(g, msg.Header.ApplicationID, d)
				if err == nil && ga != nil {
					data = GroupedData{
						AVPs: avpsToInfoList(d, msg.Header.ApplicationID, ga.AVP),
					}
				}
			} else if name == "Visited-PLMN-Id" {
				// Existing special case for PLMN.
				if os, ok := a.Data.(datatype.OctetString); ok {
					if plmn := decodePLMN([]byte(os)); plmn != nil {
						data = plmn
					}
				}
			}

			mi.AVPs = append(mi.AVPs, AVPInfo{
				Code:     a.Code,
				VendorID: a.VendorID,
				Name:     name,
				Data:     data,
			})
		}

		// Output as JSON.
		out, err := json.MarshalIndent(mi, "", "  ")
		if err != nil {
			log.Println("json marshal error:", err)
			continue
		}
		fmt.Println(string(out))
	}
}

// Lookup AVP name in the loaded dictionary.
func avpNameFromDict(d *dict.Parser, appID uint32, code uint32, vendorID uint32) string {
	// If no vendor, use UndefinedVendorID so the helper does the right thing.
	v := vendorID
	if v == 0 {
		v = dict.UndefinedVendorID
	}

	// Try app‑specific AVP first, with vendor.
	if avpDef, err := d.FindAVPWithVendor(appID, int(code), v); err == nil && avpDef != nil {
		return avpDef.Name
	}

	// Fallback to base application (appid 0) if not found.
	if avpDef, err := d.FindAVPWithVendor(0, int(code), v); err == nil && avpDef != nil {
		return avpDef.Name
	}

	return ""
}

// avpToJSONValue converts common Diameter datatypes into JSON‑friendly Go values.
func avpToJSONValue(v datatype.Type) interface{} {
	switch x := v.(type) {
	case datatype.UTF8String:
		return string(x)
	case datatype.DiameterIdentity:
		return string(x)
	case datatype.OctetString:
		return []byte(x)
	case datatype.Address:
		return x.String()
	case datatype.Integer32:
		return int32(x)
	case datatype.Unsigned32:
		return uint32(x)
	case datatype.Integer64:
		return int64(x)
	case datatype.Unsigned64:
		return uint64(x)
	case datatype.Float32:
		return float32(x)
	case datatype.Float64:
		return float64(x)
	case datatype.IPv4:
		return x.String()
	case datatype.IPv6:
		return x.String()
	case datatype.Grouped:
		return fmt.Sprintf("%x", []byte(x))
	default:
		return fmt.Sprintf("%v", v)
	}
}

// commandCodeName returns a string representation of the command code.
func commandCodeName(code uint32) string {
	switch code {
	case 316:
		return "Update-Location (ULR/ULA)"
	case 317:
		return "Cancel-Location (CLR/CLA)"
	case 318:
		return "Authentication-Information (AIR/AIA)"
	case 319:
		return "Insert-Subscriber-Data (IDR/IDA)"
	// Add more as needed from your use cases / RFCs / IANA registry.
	default:
		return ""
	}
}

// applicationName returns a string representation of the application ID.
func applicationName(id uint32) string {
	switch id {
	case 0:
		return "Diameter Base"
	case 16777251:
		return "S6a/S6d"
	// Add other application IDs you care about.
	default:
		return ""
	}
}

// commandFlagsName returns a string representation of the command flags.
func commandFlagsName(f uint8) string {
	// RFC 6733: R(0x80) P(0x40) E(0x20) T(0x10).[web:85][web:121]
	var s string
	if f&0x80 != 0 {
		s += "R" // Request
	}
	if f&0x40 != 0 {
		if s != "" {
			s += "|"
		}
		s += "P" // Proxiable
	}
	if f&0x20 != 0 {
		if s != "" {
			s += "|"
		}
		s += "E" // Error
	}
	if f&0x10 != 0 {
		if s != "" {
			s += "|"
		}
		s += "T" // Potentially re-transmitted
	}
	return s
}

func decodePLMN(b []byte) *PLMN {
	if len(b) < 3 {
		return nil
	}
	// 3GPP BCD encoding: see 29.272 / 23.003.[web:131][web:143]
	mccDigit1 := b[0] & 0x0F
	mccDigit2 := (b[0] & 0xF0) >> 4
	mccDigit3 := b[1] & 0x0F

	mncDigit3 := (b[1] & 0xF0) >> 4
	mncDigit1 := b[2] & 0x0F
	mncDigit2 := (b[2] & 0xF0) >> 4

	mcc := fmt.Sprintf("%d%d%d", mccDigit1, mccDigit2, mccDigit3)
	var mnc string
	if mncDigit3 == 0xF { // 2‑digit MNC
		mnc = fmt.Sprintf("%d%d", mncDigit1, mncDigit2)
	} else {
		mnc = fmt.Sprintf("%d%d%d", mncDigit1, mncDigit2, mncDigit3)
	}

	return &PLMN{
		MCC: mcc,
		MNC: mnc,
		Hex: fmt.Sprintf("%x", b),
	}
}

// avpsToInfoList converts a slice of AVPs to a slice of AVPInfo, using the provided dictionary and application ID.
func avpsToInfoList(d *dict.Parser, appID uint32, avps []*diam.AVP) []AVPInfo {
	out := make([]AVPInfo, 0, len(avps))
	for _, a := range avps {
		name := avpNameFromDict(d, appID, a.Code, a.VendorID)
		data := avpToJSONValue(a.Data)

		if name == "Visited-PLMN-Id" {
			if os, ok := a.Data.(datatype.OctetString); ok {
				if plmn := decodePLMN([]byte(os)); plmn != nil {
					data = plmn
				}
			}
		}

		out = append(out, AVPInfo{
			Code:     a.Code,
			VendorID: a.VendorID,
			Name:     name,
			Data:     data,
		})
	}
	return out
}
