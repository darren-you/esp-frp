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

//go:build !frps

package proxy

import (
	"net"
	"reflect"
	"time"

	"github.com/quic-go/quic-go"

	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/naming"
	"github.com/fatedier/frp/pkg/nathole"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/xtcpbinding"
)

func init() {
	RegisterProxyFactory(reflect.TypeFor[*v1.XTCPProxyConfig](), NewXTCPProxy)
}

type XTCPProxy struct {
	*BaseProxy

	cfg *v1.XTCPProxyConfig
}

func NewXTCPProxy(baseProxy *BaseProxy, cfg v1.ProxyConfigurer) Proxy {
	unwrapped, ok := cfg.(*v1.XTCPProxyConfig)
	if !ok {
		return nil
	}
	return &XTCPProxy{
		BaseProxy: baseProxy,
		cfg:       unwrapped,
	}
}

func (pxy *XTCPProxy) InWorkConn(conn net.Conn, startWorkConnMsg *msg.StartWorkConn) {
	xl := pxy.xl
	defer conn.Close()
	if pxy.clientCfg.Transport.WireProtocol != "v2" || len(pxy.clientCfg.XTCPControlID) != 32 {
		xl.Errorf("XTCP requires candidate v2 authenticated control")
		return
	}
	natHoleSidMsg, err := readNatHoleSid(conn, pxy.clientCfg.Transport.WireProtocol)
	if err != nil {
		xl.Errorf("xtcp read from workConn error: %v", err)
		return
	}

	xl.Tracef("nathole prepare start")

	// Prepare NAT traversal options
	var opts nathole.PrepareOptions
	if pxy.cfg.NatTraversal != nil && pxy.cfg.NatTraversal.DisableAssistedAddrs {
		opts.DisableAssistedAddrs = true
	}

	prepareResult, err := nathole.Prepare([]string{pxy.clientCfg.NatHoleSTUNServer}, opts)
	if err != nil {
		xl.Warnf("nathole prepare error: %v", err)
		return
	}

	xl.Infof("nathole prepare success, nat type: %s, behavior: %s, addresses: %v, assistedAddresses: %v",
		prepareResult.NatType, prepareResult.Behavior, prepareResult.Addrs, prepareResult.AssistedAddrs)
	defer prepareResult.ListenConn.Close()

	// send NatHoleClient msg to server
	transactionID := nathole.NewTransactionID()
	natHoleClientMsg := &msg.NatHoleClient{
		TransactionID: transactionID,
		ProxyName:     naming.AddUserPrefix(pxy.clientCfg.User, pxy.cfg.Name),
		Sid:           natHoleSidMsg.Sid,
		MappedAddrs:   prepareResult.Addrs,
		AssistedAddrs: prepareResult.AssistedAddrs,
	}

	identity, err := xtcpbinding.NewIdentity(xtcpbinding.Provider)
	if err != nil {
		xl.Warnf("peer identity error: %v", err)
		return
	}
	natHoleClientMsg.ControlID = pxy.clientCfg.XTCPControlID
	natHoleClientMsg.Nonce = identity.Nonce[:]
	natHoleClientMsg.SPKISHA256 = identity.SPKI[:]
	natHoleClientMsg.Certificate = identity.DER
	natHoleClientMsg.Timestamp = time.Now().Unix()
	natHoleClientMsg.SignalProof, err = xtcpbinding.SignalProof(pxy.cfg.Secretkey, xtcpbinding.Provider, natHoleClientMsg.ProxyName, natHoleClientMsg.ControlID, natHoleClientMsg.Nonce, natHoleClientMsg.SPKISHA256, natHoleClientMsg.Timestamp)
	if err != nil {
		xl.Warnf("signal proof error: %v", err)
		return
	}
	xl.Tracef("nathole exchange info start")
	natHoleRespMsg, err := nathole.ExchangeInfo(pxy.ctx, pxy.msgTransporter, transactionID, natHoleClientMsg, 5*time.Second)
	if err != nil {
		xl.Warnf("nathole exchange info error: %v", err)
		return
	}

	xl.Infof("get natHoleRespMsg, sid [%s], protocol [%s], candidate address %v, assisted address %v, detectBehavior: %+v",
		natHoleRespMsg.Sid, natHoleRespMsg.Protocol, natHoleRespMsg.CandidateAddrs,
		natHoleRespMsg.AssistedAddrs, natHoleRespMsg.DetectBehavior)

	manifest, err := xtcpbinding.Decode(natHoleRespMsg.BindingManifest, uint64(time.Now().Unix()))
	sidBytes, sidErr := hex.DecodeString(natHoleSidMsg.Sid)
	if err != nil || sidErr != nil || !bytes.Equal(sidBytes, manifest.SID[:]) || manifest.ProxyName != natHoleClientMsg.ProxyName || manifest.CheckLocal(xtcpbinding.Provider, pxy.clientCfg.XTCPControlID, identity.Nonce[:], identity.SPKI[:]) != nil {
		xl.Warnf("candidate rendezvous binding rejected")
		return
	}
	listenConn := prepareResult.ListenConn
	newListenConn, raddr, err := nathole.MakeHole(pxy.ctx, listenConn, natHoleRespMsg, []byte(pxy.cfg.Secretkey))
	if err != nil {
		listenConn.Close()
		xl.Warnf("make hole error: %v", err)
		_ = pxy.msgTransporter.Send(&msg.NatHoleReport{
			Sid:     natHoleRespMsg.Sid,
			Success: false,
		})
		return
	}
	listenConn = newListenConn
	xl.Infof("establishing nat hole connection successful, sid [%s], remoteAddr [%s]", natHoleRespMsg.Sid, raddr)

	_ = pxy.msgTransporter.Send(&msg.NatHoleReport{
		Sid:     natHoleRespMsg.Sid,
		Success: true,
	})

	pxy.listenByQUIC(listenConn, raddr, startWorkConnMsg, identity, manifest, natHoleRespMsg.PeerCertificate)
}

func readNatHoleSid(conn net.Conn, wireProtocol string) (*msg.NatHoleSid, error) {
	if wireProtocol != "v2" {
		return nil, fmt.Errorf("candidate XTCP only supports v2")
	}
	workMsgConn := msg.NewConn(conn, msg.NewReadWriter(conn, wireProtocol))
	var natHoleSidMsg msg.NatHoleSid
	if err := workMsgConn.ReadMsgInto(&natHoleSidMsg); err != nil {
		return nil, err
	}
	sid, err := hex.DecodeString(natHoleSidMsg.Sid)
	if err != nil || len(sid) != 32 {
		return nil, xtcpbinding.ErrBinding
	}
	return &natHoleSidMsg, nil
}

func (pxy *XTCPProxy) listenByQUIC(listenConn *net.UDPConn, _ *net.UDPAddr, startWorkConnMsg *msg.StartWorkConn, identity *xtcpbinding.Identity, manifest xtcpbinding.Manifest, peerCertificate []byte) {
	xl := pxy.xl
	defer listenConn.Close()

	tlsConfig, err := xtcpbinding.PeerTLS(identity, peerCertificate, manifest, xtcpbinding.Provider)
	if err != nil {
		xl.Warnf("create tls config error: %v", err)
		return
	}
	quicListener, err := quic.ListenEarly(listenConn, tlsConfig,
		&quic.Config{
			MaxIdleTimeout:        time.Duration(pxy.clientCfg.Transport.QUIC.MaxIdleTimeout) * time.Second,
			MaxIncomingStreams:    3,
			MaxIncomingUniStreams: -1,
			KeepAlivePeriod:       time.Duration(pxy.clientCfg.Transport.QUIC.KeepalivePeriod) * time.Second,
		},
	)
	if err != nil {
		xl.Warnf("dial quic error: %v", err)
		return
	}
	defer quicListener.Close()
	acceptCtx, cancel := context.WithDeadline(pxy.ctx, time.Unix(int64(manifest.ExpiresAt), 0))
	defer cancel()
	var c *quic.Conn
	for {
		candidate, err := quicListener.Accept(acceptCtx)
		if err != nil {
			xl.Warnf("candidate peer accept failed: %v", err)
			return
		}
		if _, err = xtcpbinding.DecodeMustCurrent(manifest); err != nil {
			_ = candidate.CloseWithError(1, "admission expired")
			return
		}
		proofCtx, proofCancel := context.WithTimeout(pxy.ctx, 10*time.Second)
		select {
		case <-candidate.HandshakeComplete():
			err = candidate.Context().Err()
		case <-proofCtx.Done():
			err = proofCtx.Err()
		}
		if err == nil {
			err = xtcpbinding.ExchangeProof(proofCtx, candidate, manifest, xtcpbinding.Provider)
		}
		proofCancel()
		if err != nil {
			_ = candidate.CloseWithError(1, "binding rejected")
			continue
		}
		c = candidate
		break
	}

	for {
		stream, err := c.AcceptStream(pxy.ctx)
		if err != nil {
			xl.Debugf("quic accept stream error: %v", err)
			_ = c.CloseWithError(0, "")
			return
		}
		go pxy.HandleTCPWorkConnection(netpkg.QuicStreamToNetConn(stream, c), startWorkConnMsg, []byte(pxy.cfg.Secretkey))
	}
}
