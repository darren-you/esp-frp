// Copyright 2023 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nathole

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/fatedier/frp/pkg/xtcpbinding"
	"io"
	"net"
	"strings"
	"unicode/utf8"

	"github.com/fatedier/frp/pkg/msg"
)

// Candidate authenticated SID datagrams. This is deliberately incompatible
// with upstream AES-CFB discovery packets, which carry no integrity tag.
func validSIDMessage(m *msg.NatHoleSid) bool {
	if m == nil || len(m.Sid) != 64 || len(m.TransactionID) < 1 || len(m.TransactionID) > 64 || len(m.Nonce) != 64 {
		return false
	}
	sid, err := hex.DecodeString(m.Sid)
	nonce, nonceErr := hex.DecodeString(m.Nonce)
	for _, c := range []byte(m.TransactionID) {
		if c < 32 || c == 127 {
			return false
		}
	}
	return err == nil && len(sid) == 32 && nonceErr == nil && len(nonce) == 32 && m.Sid == strings.ToLower(m.Sid) && m.Nonce == strings.ToLower(m.Nonce) && utf8.ValidString(m.TransactionID) && !strings.ContainsAny(m.TransactionID, "\x00\r\n")
}
func EncodeMessage(message msg.Message, key []byte) ([]byte, error) {
	m, ok := message.(*msg.NatHoleSid)
	if !ok || !validSIDMessage(m) || len(key) < 1 || len(key) > 128 {
		return nil, xtcpbinding.ErrBinding
	}
	body, err := json.Marshal(m)
	if err != nil || len(body) > 512 {
		return nil, xtcpbinding.ErrBinding
	}
	out := append([]byte("XHD1"), byte(len(body)>>8), byte(len(body)))
	out = append(out, body...)
	mac := hmac.New(sha256.New, key)
	mac.Write(out)
	return append(out, mac.Sum(nil)...), nil
}
func DecodeMessageInto(data, key []byte, message msg.Message) error {
	m, ok := message.(*msg.NatHoleSid)
	if !ok || m == nil || len(key) < 1 || len(key) > 128 || len(data) < 39 || len(data) > 550 || !bytes.Equal(data[:4], []byte("XHD1")) {
		return xtcpbinding.ErrBinding
	}
	size := int(binary.BigEndian.Uint16(data[4:6]))
	if size < 1 || size > 512 || len(data) != 6+size+32 {
		return xtcpbinding.ErrBinding
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(data[:6+size])
	if !hmac.Equal(mac.Sum(nil), data[6+size:]) {
		return xtcpbinding.ErrBinding
	}
	if !utf8.Valid(data[6 : 6+size]) {
		return xtcpbinding.ErrBinding
	}
	fields := json.NewDecoder(bytes.NewReader(data[6 : 6+size]))
	start, e := fields.Token()
	if e != nil || start != json.Delim('{') {
		return xtcpbinding.ErrBinding
	}
	seen := map[string]bool{}
	for fields.More() {
		token, e := fields.Token()
		name, ok := token.(string)
		if e != nil || !ok || seen[name] {
			return xtcpbinding.ErrBinding
		}
		seen[name] = true
		var value json.RawMessage
		if e = fields.Decode(&value); e != nil {
			return xtcpbinding.ErrBinding
		}
	}
	end, e := fields.Token()
	if e != nil || end != json.Delim('}') {
		return xtcpbinding.ErrBinding
	}
	var parsed msg.NatHoleSid
	decoder := json.NewDecoder(bytes.NewReader(data[6 : 6+size]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&parsed); err != nil || !validSIDMessage(&parsed) {
		return xtcpbinding.ErrBinding
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return xtcpbinding.ErrBinding
	}
	*m = parsed
	return nil
}

func ListAllLocalIPs() ([]net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func ListLocalIPsForNatHole(maxItems int) ([]string, error) {
	if maxItems <= 0 {
		return nil, fmt.Errorf("maxItems must be greater than 0")
	}

	ips, err := ListAllLocalIPs()
	if err != nil {
		return nil, err
	}

	filtered := make([]string, 0, maxItems)
	for _, ip := range ips {
		if len(filtered) >= maxItems {
			break
		}

		// ignore ipv6 address
		if ip.To4() == nil {
			continue
		}
		// ignore localhost IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}

		filtered = append(filtered, ip.String())
	}
	return filtered, nil
}
