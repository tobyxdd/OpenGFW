package oob

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"net"
	"runtime"
)

var packetSerializeOptions = gopacket.SerializeOptions{
	FixLengths:       true,
	ComputeChecksums: true,
}

type Device interface {
	Read() ([]byte, error)
	Write([]byte) error
}

type TCPHandler func(src, dst net.IP, payload []byte) (rst bool)
type UDPHandler func(src, dst net.IP, payload []byte)
type IPHandler func(src, dst net.IP, payload []byte)

type TrafficEngine struct {
	TCPHandlers []TCPHandler
	UDPHandlers []UDPHandler
	IPHandlers  []IPHandler
}

func (e *TrafficEngine) RunEthernet(device Device) error {
	readChan, writeChan, stopChan := make(chan []byte, 1024), make(chan []byte, 1024), make(chan bool)
	defer close(stopChan)
	// workers
	for i := 0; i < runtime.NumCPU(); i++ {
		go e.worker(readChan, writeChan, stopChan)
	}
	// writeChan to device
	go func() {
		for {
			select {
			case wb := <-writeChan:
				_ = device.Write(wb)
			case <-stopChan:
				return
			}
		}
	}()
	// device to readChan
	for {
		rb, err := device.Read()
		if err != nil {
			return err
		}
		readChan <- rb
	}
}

func (e *TrafficEngine) worker(readChan chan []byte, writeChan chan []byte, stopChan chan bool) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var udp layers.UDP
	var payload gopacket.Payload
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &ip6, &tcp, &udp, &payload)
	var decoded []gopacket.LayerType
	for {
		select {
		case bs := <-readChan:
			_ = parser.DecodeLayers(bs, &decoded)
			var src, dst net.IP
			var ttl uint8
			var id uint16
			var flowLabel uint32
			var isTCP, isUDP bool
			for _, layerType := range decoded {
				switch layerType {
				case layers.LayerTypeIPv4:
					src, dst, ttl, id = ip4.SrcIP, ip4.DstIP, ip4.TTL, ip4.Id
				case layers.LayerTypeIPv6:
					src, dst, ttl, flowLabel = ip6.SrcIP, ip6.DstIP, ip6.HopLimit, ip6.FlowLabel
				case layers.LayerTypeTCP:
					isTCP = true
				case layers.LayerTypeUDP:
					isUDP = true
				}
			}
			if src == nil || dst == nil {
				// Not IP protocol at all
				continue
			}
			if isTCP {
				for _, h := range e.TCPHandlers {
					rst := h(src, dst, payload)
					if rst {
						// Do TCP RST
						rstBs := tcpRST(eth.SrcMAC, eth.DstMAC, src, dst, ttl, id, flowLabel, tcp)
						if rstBs != nil {
							writeChan <- rstBs
						}
						break
					}
				}
			} else if isUDP {
				for _, h := range e.UDPHandlers {
					h(src, dst, payload)
				}
			} else {
				for _, h := range e.IPHandlers {
					h(src, dst, payload)
				}
			}
		case <-stopChan:
			return
		}
	}
}

func tcpRST(srcMAC, dstMAC net.HardwareAddr, src, dst net.IP, ttl uint8, id uint16, flowLabel uint32, tcp layers.TCP) []byte {
	buf := gopacket.NewSerializeBuffer()
	// Ethernet layer
	eth := layers.Ethernet{
		SrcMAC: srcMAC,
		DstMAC: dstMAC,
	}
	if src.To4() != nil {
		eth.EthernetType = layers.EthernetTypeIPv4
	} else {
		eth.EthernetType = layers.EthernetTypeIPv6
	}
	// TCP layer
	ntcp := layers.TCP{
		SrcPort: tcp.SrcPort,
		DstPort: tcp.DstPort,
		Seq:     tcp.Seq + uint32(len(tcp.Payload)),
		Ack:     tcp.Ack,
		RST:     true,
		Window:  tcp.Window,
	}
	// IP, can be v4 or v6
	if eth.EthernetType == layers.EthernetTypeIPv4 {
		ip := layers.IPv4{
			Version:  4,
			Id:       id + 1,
			TTL:      ttl,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    src,
			DstIP:    dst,
		}
		_ = ntcp.SetNetworkLayerForChecksum(&ip)
		if gopacket.SerializeLayers(buf, packetSerializeOptions,
			&eth,
			&ip,
			&ntcp,
			gopacket.Payload{},
		) == nil {
			return buf.Bytes()
		}
	} else {
		ip := layers.IPv6{
			Version:    6,
			FlowLabel:  flowLabel,
			NextHeader: layers.IPProtocolTCP,
			HopLimit:   ttl,
			SrcIP:      src,
			DstIP:      dst,
		}
		_ = ntcp.SetNetworkLayerForChecksum(&ip)
		if gopacket.SerializeLayers(buf, packetSerializeOptions,
			&eth,
			&ip,
			&ntcp,
			gopacket.Payload{},
		) == nil {
			return buf.Bytes()
		}
	}
	return nil
}
