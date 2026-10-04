// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"time"

	"github.com/fatedier/frp/pkg/msg"
)

func udpCodecPeer(path string, operation byte, value uint32, payload []byte, reject bool) []byte {
	var input bytes.Buffer
	input.WriteByte(operation)
	must(binary.Write(&input, binary.BigEndian, value))
	input.Write(payload)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, path)
	command.Stdin = &input
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if reject {
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 10 || len(output) != 0 {
			panic(fmt.Sprintf("UDP negative peer: err=%v output=%d stderr=%s", err, len(output), stderr.String()))
		}
	} else if err != nil {
		panic(fmt.Sprintf("UDP codec peer: %v %s", err, stderr.String()))
	}
	return output
}

func udpCodecFixture(id int) *msg.UDPPacket {
	sizes := []int{0, 1, 32, 128, 512, 1200, 1472, 4096, 49107, 65507}
	ipv4 := func(port int) *net.UDPAddr { return &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: port} }
	ipv6 := func(port int, zone string) *net.UDPAddr {
		return &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: port, Zone: zone}
	}
	packet := &msg.UDPPacket{RemoteAddr: ipv4(54321)}
	length := 0
	if id < 40 {
		length = sizes[id%10]
		if id >= 10 && id < 20 {
			packet.RemoteAddr = ipv6(1, "")
		}
		if id >= 20 {
			packet.LocalAddr = ipv4(0)
		}
		if id >= 30 {
			packet.LocalAddr = ipv6(65535, "en0")
			packet.RemoteAddr = ipv6(1, "")
			if id == 39 {
				length = 65488
			}
		}
	} else if id == 40 {
		zone := string(bytes.Repeat([]byte{'z'}, 255))
		packet.LocalAddr, packet.RemoteAddr = ipv6(0, zone), ipv6(65535, zone)
	} else if id == 41 {
		packet.RemoteAddr = &net.UDPAddr{IP: net.ParseIP("::ffff:203.0.113.9"), Port: 54321}
		length = 1472
	} else if id == 42 {
		packet.RemoteAddr, length = ipv6(0, "abcd"), 65507
	} else if id == 43 {
		packet.LocalAddr, length = ipv6(65535, "en0\x00中\U0010ffff"), 1472
	} else {
		packet.LocalAddr, packet.RemoteAddr = ipv4(65535), ipv4(0)
	}
	packet.Content = make([]byte, length)
	for i := range packet.Content {
		packet.Content[i] = byte(i*31 + id)
	}
	return packet
}

func udpOfficialPayload(packet *msg.UDPPacket) []byte {
	body, err := msg.EncodeUDPPacketBinary(packet)
	must(err)
	return append([]byte{0, byte(msg.V2TypeUDPPacketBinary)}, body...)
}

func udpCompareOfficial(payload []byte, expected *msg.UDPPacket) {
	if len(payload) < 2 || binary.BigEndian.Uint16(payload[:2]) != msg.V2TypeUDPPacketBinary {
		panic("C UDP MESSAGE type mismatch")
	}
	decoded, err := msg.DecodeUDPPacketBinary(payload[2:])
	must(err)
	if !bytes.Equal(decoded.Content, expected.Content) || decoded.RemoteAddr.String() != expected.RemoteAddr.String() ||
		(decoded.LocalAddr == nil) != (expected.LocalAddr == nil) ||
		decoded.LocalAddr != nil && decoded.LocalAddr.String() != expected.LocalAddr.String() {
		panic("official UDP decoder observed packet mismatch")
	}
}

func runUDPCodec(path string) {
	for id := 0; id < 45; id++ {
		expected := udpCodecFixture(id)
		official := udpOfficialPayload(expected)
		// Independently generated C configuration -> official Go decode and bytes.
		encoded := udpCodecPeer(path, 1, uint32(id), nil, false)
		udpCompareOfficial(encoded, expected)
		if !bytes.Equal(encoded, official) {
			panic(fmt.Sprintf("UDP fixture %d differs from official encoding", id))
		}
		// Official Go encode -> C borrow/decode/re-encode -> official Go decode.
		roundTrip := udpCodecPeer(path, 0, uint32(len(official)), official, false)
		udpCompareOfficial(roundTrip, expected)
		if !bytes.Equal(roundTrip, official) {
			panic(fmt.Sprintf("UDP fixture %d round-trip bytes differ", id))
		}
	}
	valid := udpOfficialPayload(udpCodecFixture(1))
	bad := [][]byte{{0, 19, 0}, {0, 19, 0x82}, {0, 19, 2, 9}, append(append([]byte(nil), valid...), 0)}
	wrongType := append([]byte(nil), valid...)
	wrongType[1] = byte(msg.V2TypeUDPPacket)
	bad = append(bad, wrongType)
	ipv4Zone := []byte{0, 19, 2, 4, 203, 0, 113, 9, 0, 1, 1, 'z', 0, 0}
	bad = append(bad, ipv4Zone)
	invalidUTF8 := udpOfficialPayload(&msg.UDPPacket{RemoteAddr: &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 1, Zone: "z"}})
	invalidUTF8[23] = 0xff
	bad = append(bad, invalidUTF8)
	tooLarge := append([]byte(nil), valid...)
	binary.BigEndian.PutUint16(tooLarge[11:13], 65535)
	bad = append(bad, tooLarge)
	for length := 0; length < len(valid); length++ {
		bad = append(bad, valid[:length])
	}
	for _, payload := range bad {
		if len(payload) >= 2 && binary.BigEndian.Uint16(payload[:2]) == msg.V2TypeUDPPacketBinary {
			if _, err := msg.DecodeUDPPacketBinary(payload[2:]); err == nil {
				panic("negative UDP fixture accepted by official decoder")
			}
		}
		udpCodecPeer(path, 0, uint32(len(payload)), payload, true)
	}
	oversized := make([]byte, 65537)
	udpCodecPeer(path, 0, uint32(len(oversized)), oversized, true)
	fmt.Printf("Official FRP v0.71.0 UDP binary-v1: 45 independent C encodes, 45 bidirectional cases, %d rejections passed\n", len(bad)+1)
}
