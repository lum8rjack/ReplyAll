package poisoners

import (
	"log"
	"net"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/text/encoding/charmap"
)

type packetDetails struct {
	ipType             int
	srcIP              net.IP
	dstIP              net.IP
	srcMAC             net.HardwareAddr
	dstMAC             net.HardwareAddr
	srcPort            layers.UDPPort
	dstPort            layers.UDPPort
	transactionID      []byte
	requestName        []byte
	requestNameLen     []byte
	requestNameDecoded string
}

type sendInfo struct {
	handle     *pcap.Handle
	respondIP  net.IP
	respondMAC net.HardwareAddr
	analyze    bool
}

func toUtf8(iso8859_1_buf []byte) []byte {
	r, err := charmap.ISO8859_1.NewDecoder().Bytes(iso8859_1_buf)

	if err != nil {
		log.Println("Error converting latin-1 to UTF-8")
	}
	return r
}

func toUtf82(iso8859_1_buf []byte) string {
	buf := make([]rune, len(iso8859_1_buf))
	for i, b := range iso8859_1_buf {
		buf[i] = rune(b)
	}
	return string(buf)
}
