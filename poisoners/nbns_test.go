package poisoners

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"
)

// TestEncodeNetbiosName calls poisoners.EncodeNetbiosName()
func TestEncodeNetbiosName(t *testing.T) {

	netbios := []byte("TEST")
	var netbiosArray [16]byte
	for i, c := range netbios {
		netbiosArray[i] = c
	}
	correctName := "4645454646444645434143414341434143414341434143414341434143414341"
	encoded := EncodeNetbiosName(netbiosArray)

	// Make sure the correct length is returned
	if len(encoded) != 32 {
		log.Fatalf("EncodeNetbiosName should return a byte array of length 32 but instead had length: %d\n", len(encoded))
	}

	encodedString := hex.EncodeToString(encoded[:])

	// Make sure the encoded NetBIOS name is correct
	if encodedString != correctName {
		t.Fatalf("EncodeNetbiosName = %s, should equal %s\n", encodedString, correctName)
	}
}

// TestDecodeNetbiosName calls poisoners.DecodeNetbiosName()
func TestDecodeNetbiosName(t *testing.T) {
	netbios := "4645454646444645434143414341434143414341434143414341434143414341"
	netbiosArray, _ := hex.DecodeString(netbios)
	correctNameString := "TEST"
	var encodedName [32]byte

	for i, c := range netbiosArray {
		encodedName[i] = c
	}

	decodedName := DecodeNetbiosName(encodedName)

	// Make sure the correct length is returned
	if len(decodedName) != 16 {
		log.Fatalf("DecodeNetbiosName should return a byte array of length 16 but instead had length: %d\n", len(decodedName))
	}

	var decode []byte
	decode = decodedName[:]
	decode = bytes.Trim(decode, "\x00")
	decodedNameStr := string(decode)

	// Make sure the decoded NetBIOS name is correct
	if decodedNameStr != correctNameString {
		t.Fatalf("DecodeNetbiosName = %s (length=%d), should equal %s\n", decodedNameStr, len(decodedNameStr), correctNameString)
	}
}
