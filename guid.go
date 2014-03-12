// This package provides immutable GUID structs and the functions
// NewGUID, NewUUID, and Parse() for generating version 4 GUID and UUIDs,
// as specified in RFC 4122.
// "GUID" is the term is used for a randomly generated value.
// "UUID" is the term used for an globally unique (unchanging) value that is generated using the mac address.
//
// Copyright (C) 2014 by Dalton Cherry <daltoniam@gmail.com>
package guid

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"regexp"
	"time"
)

type GUID [16]byte

//borrowing the Parse() and ParseHex() from gouuid by Krzysztof Kowalik <chris@nu7hat.ch>

// Pattern used to parse hex string representation of the GUID.
// FIXME: do something to consider both brackets at one time,
// current one allows to parse string with only one opening
// or closing bracket.
const hexPattern = "^(urn\\:uuid\\:)?\\{?([a-z0-9]{8})-([a-z0-9]{4})-" +
	"([1-5][a-z0-9]{3})-([a-z0-9]{4})-([a-z0-9]{12})\\}?$"

var re = regexp.MustCompile(hexPattern)

// ParseHex creates a GUID object from given hex string
// representation. Function accepts GUID string in following
// formats:
//
//     uuid.ParseHex("6ba7b814-9dad-11d1-80b4-00c04fd430c8")
//     uuid.ParseHex("{6ba7b814-9dad-11d1-80b4-00c04fd430c8}")
//     uuid.ParseHex("urn:uuid:6ba7b814-9dad-11d1-80b4-00c04fd430c8")
//
func ParseHex(s string) (g *GUID, err error) {
	md := re.FindStringSubmatch(s)
	if md == nil {
		err = errors.New("Invalid GUID string")
		return
	}
	hash := md[2] + md[3] + md[4] + md[5] + md[6]
	b, err := hex.DecodeString(hash)
	if err != nil {
		return
	}
	g = new(GUID)
	copy(g[:], b)
	return
}

// Parse creates a GUID object from given bytes slice.
func Parse(b []byte) (g *GUID, err error) {
	if len(b) != 16 {
		err = errors.New("Given slice is not valid GUID sequence")
		return
	}
	g = new(GUID)
	copy(g[:], b)
	return
}

// Use the net library to return all Interfaces
// and capture any errors.
func getInterfaces() []net.Interface {
	interfaces, err := net.Interfaces()
	if err != nil {
		panic("Unable to get interfaces.")
	}
	return interfaces
}

//this will return a pseudo random GUID
func NewGUID() (guid *GUID) {
	rand.Seed(time.Now().UTC().UnixNano())
	return generateGUID()
}

//this will always return the UUID based off the machine's mac address
func NewUUID() (guid *GUID) {
	interfaces := getInterfaces()
	mainInter := interfaces[0]
	for _, inter := range interfaces {
		if len(inter.HardwareAddr) > 0 {
			mainInter = inter
			break
		}
	}
	buf := bytes.NewBuffer(mainInter.HardwareAddr)
	seed, _ := binary.ReadVarint(buf)
	rand.Seed(seed)
	return generateGUID()
}

func generateGUID() (guid *GUID) {
	guid = new(GUID)
	for i := 0; i < 16; i++ {
		guid[i] = byte(rand.Intn(16))
	}
	guid[6] = (guid[6] & 0xF) | (4 << 4)
	guid[8] = (guid[8] | 0x40) & 0x7F
	return guid
}

// Returns a string version of a GUID
func (guid *GUID) String() string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", guid[0:4], guid[4:6], guid[6:8], guid[8:10], guid[10:])
}
