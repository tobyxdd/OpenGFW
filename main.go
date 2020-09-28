package main

import (
	"bytes"
	"github.com/google/gopacket/pcap"
	"github.com/tobyxdd/opengfw/oob"
	"log"
	"net"
)

var (
	devName string
	err     error
	handle  *pcap.Handle
)

type pcapDevice struct {
	Handle *pcap.Handle
}

func (d *pcapDevice) Read() ([]byte, error) {
	bs, _, err := d.Handle.ZeroCopyReadPacketData()
	return bs, err
}

func (d *pcapDevice) Write(bs []byte) error {
	return d.Handle.WritePacketData(bs)
}

func main() {

	devName = "\\Device\\NPF_{9A61554C-283B-458E-8D65-B2C9ECE47091}"

	handle, err = pcap.OpenLive(devName, 1600, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	engine := &oob.TrafficEngine{
		TCPHandlers: []oob.TCPHandler{
			func(src, dst net.IP, payload []byte) (rst bool) {
				return bytes.Contains(payload, []byte("\r\nHost: 192.168.1.1\r\n"))
			},
		},
	}
	log.Println(engine.RunEthernet(&pcapDevice{Handle: handle}))
}
