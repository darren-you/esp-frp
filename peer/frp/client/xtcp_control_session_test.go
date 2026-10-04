// Copyright 2026 The frp Authors
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

package client

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/samber/lo"
	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/proto/wire"
	"github.com/fatedier/frp/pkg/xtcpbinding"
)

func TestXTCPLoginRequiresVerifiedTokenTransport(t *testing.T) {
	for _, tc := range []struct {
		name, transport, wire, ca string
		tls                       bool
		method                    v1.AuthMethod
		binding                   bool
	}{
		{"strict-tcp", "tcp", wire.ProtocolV2, "explicit-ca.pem", true, v1.AuthMethodToken, true},
		{"strict-quic", "quic", wire.ProtocolV2, "explicit-ca.pem", true, v1.AuthMethodToken, true},
		{"no-ca", "tcp", wire.ProtocolV2, "", true, v1.AuthMethodToken, false},
		{"plaintext", "tcp", wire.ProtocolV2, "explicit-ca.pem", false, v1.AuthMethodToken, false},
		{"quic-disabled-ca-verification", "quic", wire.ProtocolV2, "explicit-ca.pem", false, v1.AuthMethodToken, false},
		{"v1", "tcp", wire.ProtocolV1, "explicit-ca.pem", true, v1.AuthMethodToken, false},
		{"non-token", "tcp", wire.ProtocolV2, "explicit-ca.pem", true, v1.AuthMethodOIDC, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := newTestControlSessionDialer(t, tc.wire, nil, nil)
			d.xtcpBindingRequired = true
			d.common.Auth.Method = tc.method
			d.common.Transport.Protocol = tc.transport
			d.common.Transport.TLS.Enable = lo.ToPtr(tc.tls)
			d.common.Transport.TLS.TrustedCaFile = tc.ca
			login, err := d.buildLoginMsg("same-run-id")
			if tc.binding {
				require.NoError(t, err)
				require.Equal(t, xtcpbinding.ALPN, login.XTCPBindingProtocol)
			} else {
				require.Error(t, err)
				require.Nil(t, login)
			}
		})
	}
}

func TestXTCPControlIdentityIsOwnedByEachLogin(t *testing.T) {
	for _, tc := range []struct {
		name             string
		id               []byte
		negotiate, valid bool
	}{
		{"fresh-owner", append([]byte{7}, make([]byte, 31)...), true, true},
		{"short-owner", make([]byte, 31), true, false},
		{"zero-owner", make([]byte, 32), true, false},
		{"missing-owner", nil, true, false},
		{"unexpected-owner", append([]byte{7}, make([]byte, 31)...), false, false},
		{"ordinary-clears-old-owner", nil, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clientRaw, serverRaw := net.Pipe()
			defer serverRaw.Close()
			require.NoError(t, serverRaw.SetDeadline(time.Now().Add(3*time.Second)))
			tracked := &trackingConn{Conn: clientRaw}
			connector := &testConnector{conn: tracked}
			d := newTestControlSessionDialer(t, wire.ProtocolV2, connector, nil)
			d.common.XTCPControlID = append([]byte{99}, make([]byte, 31)...)
			if tc.negotiate {
				d.xtcpBindingRequired = true
				d.common.Auth.Method = v1.AuthMethodToken
				d.common.Transport.TLS.Enable = lo.ToPtr(true)
				d.common.Transport.TLS.TrustedCaFile = "explicit-ca.pem"
			}
			done := make(chan error, 1)
			go func() {
				magic := make([]byte, len(wire.MagicV2))
				if _, err := io.ReadFull(serverRaw, magic); err != nil {
					done <- err
					return
				}
				if string(magic) != wire.MagicV2 {
					done <- fmt.Errorf("bad magic")
					return
				}
				wc := wire.NewConn(serverRaw)
				frame, err := wc.ReadFrame()
				if err != nil {
					done <- err
					return
				}
				var hello wire.ClientHello
				if err = wc.UnmarshalFrame(frame, &hello); err != nil {
					done <- err
					return
				}
				rw := msg.NewV2ReadWriterWithConn(wc)
				var login msg.Login
				if err = rw.ReadMsgInto(&login); err != nil {
					done <- err
					return
				}
				if (login.XTCPBindingProtocol == xtcpbinding.ALPN) != tc.negotiate {
					done <- fmt.Errorf("wrong binding negotiation")
					return
				}
				serverHello, err := wire.NewServerHello(hello)
				if err != nil {
					done <- err
					return
				}
				out, err := wire.NewJSONFrame(wire.FrameTypeServerHello, serverHello)
				if err != nil {
					done <- err
					return
				}
				if err = wc.WriteFrame(out); err != nil {
					done <- err
					return
				}
				done <- rw.WriteMsg(&msg.LoginResp{RunID: "same-run-id", XTCPControlID: tc.id})
			}()
			session, err := d.Dial("same-run-id")
			if !tc.valid {
				require.Error(t, err)
				require.Nil(t, session)
				require.True(t, tracked.closed.Load())
				require.True(t, connector.closed.Load())
			} else {
				require.NoError(t, err)
				defer session.Conn.Close()
				defer session.Connector.Close()
				require.NotSame(t, d.common, session.Common)
				require.Equal(t, byte(99), d.common.XTCPControlID[0])
				require.Equal(t, tc.id, session.Common.XTCPControlID)
				if tc.negotiate {
					session.Common.XTCPControlID[0] = 42
					require.Equal(t, byte(7), tc.id[0])
					require.Equal(t, byte(99), d.common.XTCPControlID[0])
				}
			}
			require.NoError(t, <-done)
		})
	}
}
