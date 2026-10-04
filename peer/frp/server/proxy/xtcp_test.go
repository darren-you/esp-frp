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

package proxy

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/proto/wire"
)

func TestWriteNatHoleSidUsesWireV2MessageFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	setPipeDeadline(t, client, server)

	errCh := make(chan error, 1)
	go func() {
		errCh <- writeNatHoleSid(server, wire.ProtocolV2, "1212121212121212121212121212121212121212121212121212121212121212")
	}()

	frame, err := wire.NewConn(client).ReadFrame()
	require.NoError(t, err)
	require.Equal(t, wire.FrameTypeMessage, frame.Type)
	require.GreaterOrEqual(t, len(frame.Payload), 2)
	require.Equal(t, msg.V2TypeNatHoleSid, binary.BigEndian.Uint16(frame.Payload[:2]))

	var out msg.NatHoleSid
	require.NoError(t, msg.DecodeV2MessageFrameInto(frame, &out))
	require.Equal(t, "1212121212121212121212121212121212121212121212121212121212121212", out.Sid)
	require.NoError(t, <-errCh)
}

func TestWriteNatHoleSidRejectsWireV1AndDefaultWithoutWriting(t *testing.T) {
	for _, protocol := range []string{"", wire.ProtocolV1} {
		t.Run(protocol, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			require.ErrorContains(t, writeNatHoleSid(server, protocol, "1212121212121212121212121212121212121212121212121212121212121212"), "wire v2")
			require.NoError(t, client.SetReadDeadline(time.Now().Add(30*time.Millisecond)))
			var b [1]byte
			n, err := client.Read(b[:])
			require.Zero(t, n)
			require.Error(t, err)
			require.True(t, err.(net.Error).Timeout())
		})
	}
}

func setPipeDeadline(t *testing.T, conns ...net.Conn) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for _, conn := range conns {
		require.NoError(t, conn.SetDeadline(deadline))
	}
}
