package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

type FlowKey struct {
	SourceIP string
	DestIP   string
	DestPort string
	Protocol string
}

type FlowStats struct {
	PacketCount      int
	TotalBytes       int
	StartTime        time.Time
	EndTime          time.Time
	AvgInterval      float64
	TotalTTL         int
	TCPFlags         uint8
	DNSQueryCount    int
	UniqueDNSDomains map[string]bool
	HasHTTPTraffic   bool
	HTTPMethods      map[string]bool
	LargeHTTPPost    bool
	HasTLSTraffic    bool
	TLSSNIList       map[string]bool
}

type FinalPayload struct {
	SourceIP         string   `json:"src_ip"`
	DestIP           string   `json:"dst_ip"`
	DestPort         string   `json:"dst_port"`
	Protocol         string   `json:"protocol"`
	PacketCount      int      `json:"packet_count"`
	TotalBytes       int      `json:"total_bytes"`
	DurationSec      float64  `json:"duration_seconds"`
	AvgInterval      float64  `json:"avg_interval_seconds"`
	AvgTTL           float64  `json:"avg_ttl"`
	TCPFlagsStr      string   `json:"tcp_flags,omitempty"`
	DNSQueryCount    int      `json:"dns_query_count"`
	UniqueDNSDomains []string `json:"unique_dns_domains"`
	HasHTTPTraffic   bool     `json:"has_http_traffic"`
	HTTPMethods      []string `json:"http_methods"`
	LargeHTTPPost    bool     `json:"large_http_post"`
	HasTLSTraffic    bool     `json:"has_tls_traffic"`
	TLSSNIList       []string `json:"tls_sni_list"`
	BytesPerPacket   float64  `json:"bytes_per_packet"`
	BurstScore       float64  `json:"burst_score"`
	MultiPortSameIP  bool     `json:"multi_port_same_ip"`
	IsInbound        bool     `json:"is_inbound"`
}

func getTCPFlagsStr(flags uint8) string {
	var f []string
	if flags&0x02 != 0 { f = append(f, "SYN") }
	if flags&0x10 != 0 { f = append(f, "ACK") }
	if flags&0x01 != 0 { f = append(f, "FIN") }
	if flags&0x04 != 0 { f = append(f, "RST") }
	if flags&0x08 != 0 { f = append(f, "PSH") }
	if flags&0x20 != 0 { f = append(f, "URG") }
	if len(f) == 0 {
		return "NONE"
	}
	return strings.Join(f, "|")
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("[FATAL] Harap masukkan path file PCAP/PCAPNG sebagai argumen! Contoh: extractor.exe target.pcapng")
	}
	pcapFile := os.Args[1]

	f, err := os.Open(pcapFile)
	if err != nil {
		log.Fatalf("[FATAL] Gagal buka file %s. Pastikan file ada!", pcapFile)
	}
	defer f.Close()

	var rNg *pcapgo.NgReader
	var rLegacy *pcapgo.Reader
	var isNg bool

	rNg, err = pcapgo.NewNgReader(f, pcapgo.DefaultNgReaderOptions)
	if err == nil {
		isNg = true
		fmt.Println("[*] Mendeteksi format file: PCAPNG")
	} else {
		_, errSeek := f.Seek(0, 0)
		if errSeek != nil {
			log.Fatalf("[FATAL] Gagal me-reset pointer file: %v", errSeek)
		}
		rLegacy, err = pcapgo.NewReader(f)
		if err != nil {
			log.Fatalf("[FATAL] File bukan PCAP atau PCAPNG yang valid: %v", err)
		}
		isNg = false
		fmt.Println("[*] Mendeteksi format file: Legacy PCAP")
	}

	flowTable := make(map[FlowKey]*FlowStats)
	fmt.Println("[*] Memulai ekstraksi dan agregasi PCAP/PCAPNG secara real-time...")

	var linkType layers.LinkType
	if isNg {
		linkType = rNg.LinkType()
	} else {
		linkType = rLegacy.LinkType()
	}

	for {
		var data []byte
		var captureInfo gopacket.CaptureInfo

		if isNg {
			data, captureInfo, err = rNg.ReadPacketData()
		} else {
			data, captureInfo, err = rLegacy.ReadPacketData()
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			continue
		}

		packet := gopacket.NewPacket(data, linkType, gopacket.Default)
		var srcIP, dstIP, protocol, dstPort string
		var ttl int

		if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
			ip, _ := ipLayer.(*layers.IPv4)
			srcIP = ip.SrcIP.String()
			dstIP = ip.DstIP.String()
			protocol = ip.Protocol.String()
			ttl = int(ip.TTL)
		} else {
			continue
		}

		var flags uint8 = 0
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			dstPort = tcp.DstPort.String()
			if tcp.FIN { flags |= 0x01 }
			if tcp.SYN { flags |= 0x02 }
			if tcp.RST { flags |= 0x04 }
			if tcp.PSH { flags |= 0x08 }
			if tcp.ACK { flags |= 0x10 }
			if tcp.URG { flags |= 0x20 }
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			dstPort = udp.DstPort.String()
		} else {
			dstPort = "Unknown"
		}

		key := FlowKey{SourceIP: srcIP, DestIP: dstIP, DestPort: dstPort, Protocol: protocol}

		var stats *FlowStats
		if s, exists := flowTable[key]; exists {
			stats = s
			stats.PacketCount++
			stats.TotalBytes += len(data)
			stats.EndTime = captureInfo.Timestamp
			stats.TotalTTL += ttl
			stats.TCPFlags |= flags
		} else {
			stats = &FlowStats{
				PacketCount:      1,
				TotalBytes:       len(data),
				StartTime:        captureInfo.Timestamp,
				EndTime:          captureInfo.Timestamp,
				TotalTTL:         ttl,
				TCPFlags:         flags,
				UniqueDNSDomains: make(map[string]bool),
				HTTPMethods:      make(map[string]bool),
				TLSSNIList:       make(map[string]bool),
			}
			flowTable[key] = stats
		}

		
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)
			stats.DNSQueryCount += len(dns.Questions)
			for _, q := range dns.Questions {
				stats.UniqueDNSDomains[string(q.Name)] = true
			}
		}

		
		if appLayer := packet.ApplicationLayer(); appLayer != nil {
			payload := appLayer.Payload()
			
			
			if len(payload) > 50 && payload[0] == 0x16 && payload[5] == 0x01 {
				stats.HasTLSTraffic = true
				var currentStr strings.Builder
				for _, b := range payload {
					if b >= 32 && b <= 126 {
						currentStr.WriteByte(b)
					} else {
						if currentStr.Len() > 4 && strings.Contains(currentStr.String(), ".") {
							if !strings.Contains(currentStr.String(), " ") {
								stats.TLSSNIList[currentStr.String()] = true
							}
						}
							currentStr.Reset()
					}
				}
			}

			
			payloadStr := string(payload)
			if strings.HasPrefix(payloadStr, "GET ") || strings.HasPrefix(payloadStr, "POST ") || strings.HasPrefix(payloadStr, "PUT ") || strings.HasPrefix(payloadStr, "HEAD ") {
				stats.HasHTTPTraffic = true
				method := strings.SplitN(payloadStr, " ", 2)[0]
				stats.HTTPMethods[method] = true
				if method == "POST" && len(payload) > 50000 {
					stats.LargeHTTPPost = true
				}
			}
		}
	}

	
	dstPortCounts := make(map[string]map[string]bool)
	for key := range flowTable {
		if dstPortCounts[key.DestIP] == nil {
			dstPortCounts[key.DestIP] = make(map[string]bool)
		}
		dstPortCounts[key.DestIP][key.DestPort] = true
	}

	var payload []FinalPayload
	for key, stats := range flowTable {
		duration := stats.EndTime.Sub(stats.StartTime).Seconds()
		avgInterval := 0.0
		if stats.PacketCount > 1 {
			avgInterval = duration / float64(stats.PacketCount-1)
		}
		
		avgTTL := float64(stats.TotalTTL) / float64(stats.PacketCount)

		
		bytesPerPkt := 0.0
		if stats.PacketCount > 0 {
			bytesPerPkt = float64(stats.TotalBytes) / float64(stats.PacketCount)
		}
		burstScore := float64(stats.PacketCount) / math.Max(duration, 1.0)

		
		isInbound := false
		if !strings.HasPrefix(key.SourceIP, "10.") && !strings.HasPrefix(key.SourceIP, "192.168.") && !strings.HasPrefix(key.SourceIP, "172.") {
			isInbound = true
		}

		multiPort := len(dstPortCounts[key.DestIP]) > 3

		if stats.PacketCount > 3 {
			payload = append(payload, FinalPayload{
				SourceIP:         key.SourceIP,
				DestIP:           key.DestIP,
				DestPort:         key.DestPort,
				Protocol:         key.Protocol,
				PacketCount:      stats.PacketCount,
				TotalBytes:       stats.TotalBytes,
				DurationSec:      duration,
				AvgInterval:      avgInterval,
				AvgTTL:           avgTTL,
				TCPFlagsStr:      getTCPFlagsStr(stats.TCPFlags),
				DNSQueryCount:    stats.DNSQueryCount,
				UniqueDNSDomains: mapKeys(stats.UniqueDNSDomains),
				HasHTTPTraffic:   stats.HasHTTPTraffic,
				HTTPMethods:      mapKeys(stats.HTTPMethods),
				LargeHTTPPost:    stats.LargeHTTPPost,
				HasTLSTraffic:    stats.HasTLSTraffic,
				TLSSNIList:       mapKeys(stats.TLSSNIList),
				BytesPerPacket:   bytesPerPkt,
				BurstScore:       burstScore,
				MultiPortSameIP:  multiPort,
				IsInbound:        isInbound,
			})
		}
	}

	jsonData, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		log.Fatalf("[FATAL] Gagal membuat JSON: %v", err)
	}

	err = os.WriteFile("output.json", jsonData, 0644)
	if err != nil {
		log.Fatalf("[FATAL] Gagal menulis ke file output.json: %v", err)
	}

	fmt.Println("[+] Berhasil menyimpan hasil agregasi mendalam ke output.json")
}
