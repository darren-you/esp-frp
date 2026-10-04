// Copyright 2017 fatedier, fatedier@gmail.com
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

package visitor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	libio "github.com/fatedier/golib/io"
	quic "github.com/quic-go/quic-go"
	"golang.org/x/time/rate"

	"bytes"
	"encoding/hex"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/naming"
	"github.com/fatedier/frp/pkg/nathole"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/xlog"
	"github.com/fatedier/frp/pkg/xtcpbinding"
)

var ErrNoTunnelSession = errors.New("no tunnel session")

type XTCPVisitor struct {
	*BaseVisitor
	session       TunnelSession
	startTunnelCh chan struct{}
	retryLimiter  *rate.Limiter
	cancel        context.CancelFunc

	cfg *v1.XTCPVisitorConfig
}

func (sv *XTCPVisitor) Run() (err error) {
	sv.ctx, sv.cancel = context.WithCancel(sv.ctx)

	if sv.cfg.Protocol != "quic" || sv.cfg.FallbackTo != "" || sv.clientCfg.Transport.WireProtocol != "v2" || len(sv.clientCfg.XTCPControlID) != 32 {
		return fmt.Errorf("XTCP requires candidate v2 control and bound QUIC")
	}
	sv.session = NewQUICTunnelSession(sv.clientCfg)

	if sv.cfg.BindPort > 0 {
		sv.l, err = net.Listen("tcp", net.JoinHostPort(sv.cfg.BindAddr, strconv.Itoa(sv.cfg.BindPort)))
		if err != nil {
			return
		}
		go sv.acceptLoop(sv.l, "xtcp local", sv.handleConn)
	}

	go sv.acceptLoop(sv.internalLn, "xtcp internal", sv.handleConn)
	go sv.processTunnelStartEvents()
	if sv.cfg.KeepTunnelOpen {
		sv.retryLimiter = rate.NewLimiter(rate.Every(time.Hour/time.Duration(sv.cfg.MaxRetriesAnHour)), sv.cfg.MaxRetriesAnHour)
		go sv.keepTunnelOpenWorker()
	}

	if sv.plugin != nil {
		sv.plugin.Start()
	}
	return
}

func (sv *XTCPVisitor) Close() {
	sv.mu.Lock()
	defer sv.mu.Unlock()
	sv.BaseVisitor.Close()
	if sv.cancel != nil {
		sv.cancel()
	}
	if sv.session != nil {
		sv.session.Close()
	}
}

func (sv *XTCPVisitor) processTunnelStartEvents() {
	for {
		select {
		case <-sv.ctx.Done():
			return
		case <-sv.startTunnelCh:
			start := time.Now()
			sv.makeNatHole()
			duration := time.Since(start)
			// avoid too frequently
			if duration < 10*time.Second {
				timer := time.NewTimer(10*time.Second - duration)
				select {
				case <-sv.ctx.Done():
					timer.Stop()
					return
				case <-timer.C:
				}
			}
		}
	}
}

func (sv *XTCPVisitor) keepTunnelOpenWorker() {
	xl := xlog.FromContextSafe(sv.ctx)
	ticker := time.NewTicker(time.Duration(sv.cfg.MinRetryInterval) * time.Second)
	defer ticker.Stop()

	sv.startTunnelCh <- struct{}{}
	for {
		select {
		case <-sv.ctx.Done():
			return
		case <-ticker.C:
			xl.Debugf("keepTunnelOpenWorker try to check tunnel...")
			conn, err := sv.getTunnelConn(sv.ctx)
			if err != nil {
				xl.Warnf("keepTunnelOpenWorker get tunnel connection error: %v", err)
				_ = sv.retryLimiter.Wait(sv.ctx)
				continue
			}
			xl.Debugf("keepTunnelOpenWorker check success")
			if conn != nil {
				conn.Close()
			}
		}
	}
}

func (sv *XTCPVisitor) handleConn(userConn net.Conn) {
	xl := xlog.FromContextSafe(sv.ctx)
	isConnTransferred := false
	var tunnelErr error
	defer func() {
		if !isConnTransferred {
			// If there was an error and connection supports CloseWithError, use it
			if tunnelErr != nil {
				if eConn, ok := userConn.(interface{ CloseWithError(error) error }); ok {
					_ = eConn.CloseWithError(tunnelErr)
					return
				}
			}
			userConn.Close()
		}
	}()

	xl.Debugf("get a new xtcp user connection")

	tunnelConn, err := sv.openTunnel(sv.ctx)
	if err != nil {
		xl.Errorf("open tunnel error: %v", err)
		tunnelErr = err
		return
	}

	muxConnRWCloser, recycleFn, err := wrapVisitorConn(tunnelConn, sv.cfg.GetBaseConfig())
	if err != nil {
		xl.Errorf("%v", err)
		tunnelConn.Close()
		tunnelErr = err
		return
	}
	defer recycleFn()

	_, _, errs := libio.Join(userConn, muxConnRWCloser)
	xl.Debugf("join connections closed")
	if len(errs) > 0 {
		xl.Tracef("join connections errors: %v", errs)
	}
}

// openTunnel will open a tunnel connection to the target server.
func (sv *XTCPVisitor) openTunnel(ctx context.Context) (conn net.Conn, err error) {
	xl := xlog.FromContextSafe(sv.ctx)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-sv.ctx.Done():
			return nil, sv.ctx.Err()
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return nil, fmt.Errorf("open tunnel timeout")
			}
			return nil, ctx.Err()
		case <-timer.C:
			conn, err = sv.getTunnelConn(ctx)
			if err != nil {
				if !errors.Is(err, ErrNoTunnelSession) {
					xl.Warnf("get tunnel connection error: %v", err)
				}
				timer.Reset(500 * time.Millisecond)
				continue
			}
			return conn, nil
		}
	}
}

func (sv *XTCPVisitor) getTunnelConn(ctx context.Context) (net.Conn, error) {
	conn, err := sv.session.OpenConn(ctx)
	if err == nil {
		return conn, nil
	}
	sv.session.Close()

	select {
	case sv.startTunnelCh <- struct{}{}:
	default:
	}
	return nil, err
}

// 0. PreCheck
// 1. Prepare
// 2. ExchangeInfo
// 3. MakeNATHole
// 4. Create a tunnel session using an underlying UDP connection.
func (sv *XTCPVisitor) makeNatHole() {
	xl := xlog.FromContextSafe(sv.ctx)
	targetProxyName := naming.BuildTargetServerProxyName(sv.clientCfg.User, sv.cfg.ServerUser, sv.cfg.ServerName)
	xl.Tracef("makeNatHole start")
	if err := nathole.PreCheck(sv.ctx, sv.helper.MsgTransporter(), targetProxyName, 5*time.Second); err != nil {
		xl.Warnf("nathole precheck error: %v", err)
		return
	}

	xl.Tracef("nathole prepare start")

	// Prepare NAT traversal options
	var opts nathole.PrepareOptions
	if sv.cfg.NatTraversal != nil && sv.cfg.NatTraversal.DisableAssistedAddrs {
		opts.DisableAssistedAddrs = true
	}

	prepareResult, err := nathole.Prepare([]string{sv.clientCfg.NatHoleSTUNServer}, opts)
	if err != nil {
		xl.Warnf("nathole prepare error: %v", err)
		return
	}

	xl.Infof("nathole prepare success, nat type: %s, behavior: %s, addresses: %v, assistedAddresses: %v",
		prepareResult.NatType, prepareResult.Behavior, prepareResult.Addrs, prepareResult.AssistedAddrs)

	listenConn := prepareResult.ListenConn

	identity, err := xtcpbinding.NewIdentity(xtcpbinding.Visitor)
	if err != nil {
		listenConn.Close()
		xl.Warnf("peer identity failed: %v", err)
		return
	}
	// send NatHoleVisitor to server
	now := time.Now().Unix()
	transactionID := nathole.NewTransactionID()
	natHoleVisitorMsg := &msg.NatHoleVisitor{
		TransactionID: transactionID,
		ProxyName:     targetProxyName,
		Protocol:      sv.cfg.Protocol,

		Timestamp:     now,
		MappedAddrs:   prepareResult.Addrs,
		AssistedAddrs: prepareResult.AssistedAddrs,
	}

	natHoleVisitorMsg.ControlID = sv.clientCfg.XTCPControlID
	natHoleVisitorMsg.Nonce = identity.Nonce[:]
	natHoleVisitorMsg.SPKISHA256 = identity.SPKI[:]
	natHoleVisitorMsg.Certificate = identity.DER
	natHoleVisitorMsg.SignalProof, err = xtcpbinding.SignalProof(sv.cfg.SecretKey, xtcpbinding.Visitor, targetProxyName, natHoleVisitorMsg.ControlID, natHoleVisitorMsg.Nonce, natHoleVisitorMsg.SPKISHA256, now)
	if err != nil {
		listenConn.Close()
		xl.Warnf("signal capability failed: %v", err)
		return
	}
	xl.Tracef("nathole exchange info start")
	natHoleRespMsg, err := nathole.ExchangeInfo(sv.ctx, sv.helper.MsgTransporter(), transactionID, natHoleVisitorMsg, 5*time.Second)
	if err != nil {
		listenConn.Close()
		xl.Warnf("nathole exchange info error: %v", err)
		return
	}

	xl.Infof("get natHoleRespMsg, sid [%s], protocol [%s], candidate address %v, assisted address %v, detectBehavior: %+v",
		natHoleRespMsg.Sid, natHoleRespMsg.Protocol, natHoleRespMsg.CandidateAddrs,
		natHoleRespMsg.AssistedAddrs, natHoleRespMsg.DetectBehavior)

	manifest, err := xtcpbinding.Decode(natHoleRespMsg.BindingManifest, uint64(time.Now().Unix()))
	sid, sidErr := hex.DecodeString(natHoleRespMsg.Sid)
	if err != nil || sidErr != nil || !bytes.Equal(sid, manifest.SID[:]) || manifest.ProxyName != targetProxyName || manifest.CheckLocal(xtcpbinding.Visitor, sv.clientCfg.XTCPControlID, identity.Nonce[:], identity.SPKI[:]) != nil {
		listenConn.Close()
		xl.Warnf("candidate rendezvous binding rejected")
		return
	}
	newListenConn, raddr, err := nathole.MakeHole(sv.ctx, listenConn, natHoleRespMsg, []byte(sv.cfg.SecretKey))
	if err != nil {
		listenConn.Close()
		xl.Warnf("make hole error: %v", err)
		return
	}
	listenConn = newListenConn
	xl.Infof("establishing nat hole connection successful, sid [%s], remoteAddr [%s]", natHoleRespMsg.Sid, raddr)

	if err := sv.session.Init(sv.ctx, listenConn, raddr, identity, manifest, natHoleRespMsg.PeerCertificate); err != nil {
		listenConn.Close()
		xl.Warnf("init tunnel session error: %v", err)
		return
	}
}

type TunnelSession interface {
	Init(ctx context.Context, listenConn *net.UDPConn, raddr *net.UDPAddr, identity *xtcpbinding.Identity, manifest xtcpbinding.Manifest, peerCertificate []byte) error
	OpenConn(context.Context) (net.Conn, error)
	Close()
}

type QUICTunnelSession struct {
	session    *quic.Conn
	listenConn *net.UDPConn
	mu         sync.RWMutex

	clientCfg *v1.ClientCommonConfig
}

func NewQUICTunnelSession(clientCfg *v1.ClientCommonConfig) TunnelSession {
	return &QUICTunnelSession{
		clientCfg: clientCfg,
	}
}

func (qs *QUICTunnelSession) Init(ctx context.Context, listenConn *net.UDPConn, raddr *net.UDPAddr, identity *xtcpbinding.Identity, manifest xtcpbinding.Manifest, peerCertificate []byte) error {
	if _, err := xtcpbinding.DecodeMustCurrent(manifest); err != nil {
		return err
	}
	peerCtx, peerCancel := context.WithTimeout(ctx, 10*time.Second)
	defer peerCancel()
	tlsConfig, err := xtcpbinding.PeerTLS(identity, peerCertificate, manifest, xtcpbinding.Visitor)
	if err != nil {
		return fmt.Errorf("create tls config error: %v", err)
	}
	quicConn, err := quic.Dial(peerCtx, listenConn, raddr, tlsConfig,
		&quic.Config{
			MaxIdleTimeout:        time.Duration(qs.clientCfg.Transport.QUIC.MaxIdleTimeout) * time.Second,
			MaxIncomingStreams:    3,
			MaxIncomingUniStreams: -1,
			KeepAlivePeriod:       time.Duration(qs.clientCfg.Transport.QUIC.KeepalivePeriod) * time.Second,
		})
	if err != nil {
		return fmt.Errorf("dial quic error: %v", err)
	}
	err = xtcpbinding.ExchangeProof(peerCtx, quicConn, manifest, xtcpbinding.Visitor)
	if err != nil {
		_ = quicConn.CloseWithError(1, "binding rejected")
		return err
	}
	qs.mu.Lock()
	if err = ctx.Err(); err != nil {
		qs.mu.Unlock()
		_ = quicConn.CloseWithError(1, "cancelled")
		return err
	}
	qs.session = quicConn
	qs.listenConn = listenConn
	qs.mu.Unlock()
	return nil
}

func (qs *QUICTunnelSession) OpenConn(ctx context.Context) (net.Conn, error) {
	qs.mu.RLock()
	defer qs.mu.RUnlock()
	session := qs.session
	if session == nil {
		return nil, ErrNoTunnelSession
	}
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return netpkg.QuicStreamToNetConn(stream, session), nil
}

func (qs *QUICTunnelSession) Close() {
	qs.mu.Lock()
	defer qs.mu.Unlock()
	if qs.session != nil {
		_ = qs.session.CloseWithError(0, "")
		qs.session = nil
	}
	if qs.listenConn != nil {
		_ = qs.listenConn.Close()
		qs.listenConn = nil
	}
}
