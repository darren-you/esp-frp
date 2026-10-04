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
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/fatedier/frp/pkg/xtcpbinding"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/util"
)

// NatHoleTimeout seconds.
var NatHoleTimeout int64 = 10

func NewTransactionID() string {
	id, _ := util.RandID()
	return fmt.Sprintf("%d%s", time.Now().Unix(), id)
}

type ClientCfg struct {
	name         string
	sk           string
	allowUsers   []string
	sidCh        chan string
	ownerControl [32]byte
	closed       chan struct{}
}

type Session struct {
	sid            string
	analysisKey    string
	recommandMode  int
	recommandIndex int

	visitorMsg         *msg.NatHoleVisitor
	visitorTransporter transport.MessageTransporter
	vResp              *msg.NatHoleResp
	vNatFeature        *NatFeature
	vBehavior          RecommandBehavior

	clientMsg         *msg.NatHoleClient
	clientTransporter transport.MessageTransporter
	cResp             *msg.NatHoleResp
	cNatFeature       *NatFeature
	cBehavior         RecommandBehavior

	notifyCh        chan struct{}
	visitorControl  [32]byte
	providerControl [32]byte
	doneCh          chan struct{}
}

func (s *Session) genAnalysisKey() {
	hash := md5.New()
	vIPs := slices.Compact(parseIPs(s.visitorMsg.MappedAddrs))
	if len(vIPs) > 0 {
		hash.Write([]byte(vIPs[0]))
	}
	hash.Write([]byte(s.vNatFeature.NatType))
	hash.Write([]byte(s.vNatFeature.Behavior))
	hash.Write([]byte(strconv.FormatBool(s.vNatFeature.RegularPortsChange)))

	cIPs := slices.Compact(parseIPs(s.clientMsg.MappedAddrs))
	if len(cIPs) > 0 {
		hash.Write([]byte(cIPs[0]))
	}
	hash.Write([]byte(s.cNatFeature.NatType))
	hash.Write([]byte(s.cNatFeature.Behavior))
	hash.Write([]byte(strconv.FormatBool(s.cNatFeature.RegularPortsChange)))
	s.analysisKey = hex.EncodeToString(hash.Sum(nil))
}

type Controller struct {
	controls   map[[32]byte]struct{}
	clientCfgs map[string]*ClientCfg
	sessions   map[string]*Session
	analyzer   *Analyzer

	mu sync.RWMutex
}

func NewController(analysisDataReserveDuration time.Duration) (*Controller, error) {
	return &Controller{
		controls:   make(map[[32]byte]struct{}),
		clientCfgs: make(map[string]*ClientCfg),
		sessions:   make(map[string]*Session),
		analyzer:   NewAnalyzer(analysisDataReserveDuration),
	}, nil
}

func (c *Controller) CleanWorker(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			start := time.Now()
			count, total := c.analyzer.Clean()
			log.Tracef("clean %d/%d nathole analysis data, cost %v", count, total, time.Since(start))
		case <-ctx.Done():
			return
		}
	}
}

// RegisterControl is called only for a newly authenticated real server control.
// This RAM set synchronizes asynchronous handler admission with control close.
func (c *Controller) RegisterControl(controlID []byte) error {
	id, err := xtcpbinding.ID(controlID)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.controls[id]; exists {
		return xtcpbinding.ErrBinding
	}
	c.controls[id] = struct{}{}
	return nil
}
func (c *Controller) ListenClient(name string, sk string, allowUsers []string, ownerControlID []byte) (chan string, error) {
	owner, err := xtcpbinding.ID(ownerControlID)
	if err != nil {
		return nil, err
	}
	cfg := &ClientCfg{
		ownerControl: owner,
		closed:       make(chan struct{}),
		name:         name,
		sk:           sk,
		allowUsers:   allowUsers,
		sidCh:        make(chan string),
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, active := c.controls[owner]; !active {
		return nil, xtcpbinding.ErrBinding
	}
	if _, ok := c.clientCfgs[name]; ok {
		return nil, fmt.Errorf("proxy [%s] is repeated", name)
	}
	c.clientCfgs[name] = cfg
	return cfg.sidCh, nil
}

func (c *Controller) CloseClient(name string, ownerControlID []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cfg, ok := c.clientCfgs[name]
	if !ok || !hmac.Equal(ownerControlID, cfg.ownerControl[:]) {
		return
	}
	delete(c.clientCfgs, name)
	close(cfg.closed)
	for sid, session := range c.sessions {
		if session.visitorMsg.ProxyName == name && session.providerControl == cfg.ownerControl {
			delete(c.sessions, sid)
			close(session.doneCh)
		}
	}
}

// CloseControl cancels all RAM rendezvous owned by this actual authenticated
// control object. It does not persist identities or affect a replacement control.
func (c *Controller) CloseControl(controlID []byte) {
	id, err := xtcpbinding.ID(controlID)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.controls, id)
	for name, cfg := range c.clientCfgs {
		if hmac.Equal(controlID, cfg.ownerControl[:]) {
			delete(c.clientCfgs, name)
			close(cfg.closed)
		}
	}
	for sid, session := range c.sessions {
		if hmac.Equal(controlID, session.providerControl[:]) || hmac.Equal(controlID, session.visitorControl[:]) {
			delete(c.sessions, sid)
			close(session.doneCh)
		}
	}
}

func (c *Controller) GenSid() string {
	var id [32]byte
	if _, err := rand.Read(id[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(id[:])
}

func (c *Controller) HandleVisitor(m *msg.NatHoleVisitor, transporter transport.MessageTransporter, visitorUser string, callerControlID []byte) {
	caller, identityErr := xtcpbinding.ID(callerControlID)
	if identityErr != nil {
		_ = transporter.Send(c.GenNatHoleResponse(m.TransactionID, nil, "candidate authenticated control required"))
		return
	}
	if m.PreCheck {
		c.mu.RLock()
		_, active := c.controls[caller]
		cfg, ok := c.clientCfgs[m.ProxyName]
		c.mu.RUnlock()
		if !active {
			_ = transporter.Send(c.GenNatHoleResponse(m.TransactionID, nil, "closed control"))
			return
		}
		if !ok {
			_ = transporter.Send(c.GenNatHoleResponse(m.TransactionID, nil, fmt.Sprintf("xtcp server for [%s] doesn't exist", m.ProxyName)))
			return
		}
		if !slices.Contains(cfg.allowUsers, visitorUser) && !slices.Contains(cfg.allowUsers, "*") {
			_ = transporter.Send(c.GenNatHoleResponse(m.TransactionID, nil, fmt.Sprintf("xtcp visitor user [%s] not allowed for [%s]", visitorUser, m.ProxyName)))
			return
		}
		_ = transporter.Send(c.GenNatHoleResponse(m.TransactionID, nil, ""))
		return
	}

	sid := c.GenSid()
	if sid == "" {
		_ = transporter.Send(c.GenNatHoleResponse(m.TransactionID, nil, "SID entropy failure"))
		return
	}
	session := &Session{
		sid:                sid,
		visitorControl:     caller,
		doneCh:             make(chan struct{}),
		visitorMsg:         m,
		visitorTransporter: transporter,
		notifyCh:           make(chan struct{}, 1),
	}
	var (
		clientCfg *ClientCfg
		ok        bool
	)
	err := func() error {
		c.mu.Lock()
		defer c.mu.Unlock()

		if _, active := c.controls[caller]; !active {
			return xtcpbinding.ErrBinding
		}
		clientCfg, ok = c.clientCfgs[m.ProxyName]
		if !ok {
			return fmt.Errorf("xtcp server for [%s] doesn't exist", m.ProxyName)
		}
		if !slices.Contains(clientCfg.allowUsers, visitorUser) && !slices.Contains(clientCfg.allowUsers, "*") {
			return fmt.Errorf("xtcp visitor user [%s] not allowed for [%s]", visitorUser, m.ProxyName)
		}
		if m.Protocol != "quic" || time.Now().Unix()-m.Timestamp > 5 || m.Timestamp-time.Now().Unix() > 5 || !hmac.Equal(m.ControlID, caller[:]) {
			return xtcpbinding.ErrBinding
		}
		proof, err := xtcpbinding.SignalProof(clientCfg.sk, xtcpbinding.Visitor, m.ProxyName, m.ControlID, m.Nonce, m.SPKISHA256, m.Timestamp)
		if err != nil || !hmac.Equal(m.SignalProof, proof) {
			return xtcpbinding.ErrBinding
		}
		if _, err := xtcpbinding.ValidateCertificate(xtcpbinding.Visitor, m.Certificate, m.SPKISHA256); err != nil {
			return err
		}
		session.providerControl = clientCfg.ownerControl
		c.sessions[sid] = session
		return nil
	}()
	if err != nil {
		log.Warnf("handle visitorMsg error: %v", err)
		_ = transporter.Send(c.GenNatHoleResponse(m.TransactionID, nil, err.Error()))
		return
	}
	log.Tracef("handle visitor message, sid [%s], server name: %s", sid, m.ProxyName)

	defer func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.sessions[sid] == session {
			delete(c.sessions, sid)
			close(session.doneCh)
		}
	}()

	select {
	case clientCfg.sidCh <- sid:
	case <-clientCfg.closed:
		return
	case <-session.doneCh:
		return
	}

	// wait for NatHoleClient message
	select {
	case <-session.notifyCh:
	case <-session.doneCh:
		return
	case <-clientCfg.closed:
		return
	case <-time.After(time.Duration(NatHoleTimeout) * time.Second):
		log.Debugf("wait for NatHoleClient message timeout, sid [%s]", sid)
		return
	}

	select {
	case <-session.doneCh:
		return
	case <-clientCfg.closed:
		return
	default:
	}
	// Make hole-punching decisions based on the NAT information of the client and visitor.
	vResp, cResp, err := c.analysis(session)
	if err != nil {
		log.Debugf("sid [%s] analysis error: %v", err)
		vResp = c.GenNatHoleResponse(session.visitorMsg.TransactionID, nil, err.Error())
		cResp = c.GenNatHoleResponse(session.clientMsg.TransactionID, nil, err.Error())
	}
	session.cResp = cResp
	session.vResp = vResp

	// send response to visitor and client
	var g errgroup.Group
	g.Go(func() error {
		// if it's sender, wait for a while to make sure the client has send the detect messages
		if vResp.DetectBehavior.Role == "sender" {
			time.Sleep(1 * time.Second)
		}
		_ = session.visitorTransporter.Send(vResp)
		return nil
	})
	g.Go(func() error {
		// if it's sender, wait for a while to make sure the client has send the detect messages
		if cResp.DetectBehavior.Role == "sender" {
			time.Sleep(1 * time.Second)
		}
		_ = session.clientTransporter.Send(cResp)
		return nil
	})
	_ = g.Wait()

	select {
	case <-time.After(time.Duration(cResp.DetectBehavior.ReadTimeoutMs+30000) * time.Millisecond):
	case <-session.doneCh:
	case <-clientCfg.closed:
	}
}

func (c *Controller) HandleClient(m *msg.NatHoleClient, transporter transport.MessageTransporter, callerControlID []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	caller, err := xtcpbinding.ID(callerControlID)
	if err != nil {
		return
	}
	if _, active := c.controls[caller]; !active {
		return
	}
	session, ok := c.sessions[m.Sid]
	if !ok {
		return
	}
	if session.clientMsg != nil || m.ProxyName != session.visitorMsg.ProxyName || !hmac.Equal(callerControlID, session.providerControl[:]) || !hmac.Equal(m.ControlID, callerControlID) {
		return
	}
	cfg, ok := c.clientCfgs[m.ProxyName]
	if !ok || cfg.ownerControl != session.providerControl || time.Now().Unix()-m.Timestamp > 5 || m.Timestamp-time.Now().Unix() > 5 {
		return
	}
	proof, err := xtcpbinding.SignalProof(cfg.sk, xtcpbinding.Provider, m.ProxyName, m.ControlID, m.Nonce, m.SPKISHA256, m.Timestamp)
	if err != nil || !hmac.Equal(m.SignalProof, proof) {
		return
	}
	if _, err := xtcpbinding.ValidateCertificate(xtcpbinding.Provider, m.Certificate, m.SPKISHA256); err != nil {
		return
	}
	log.Tracef("handle client message, sid [%s], server name: %s", session.sid, m.ProxyName)
	session.clientMsg = m
	session.clientTransporter = transporter
	select {
	case session.notifyCh <- struct{}{}:
	default:
	}
}

func (c *Controller) HandleReport(m *msg.NatHoleReport, callerControlID []byte) {
	c.mu.RLock()
	caller, idErr := xtcpbinding.ID(callerControlID)
	_, active := c.controls[caller]
	session, ok := c.sessions[m.Sid]
	c.mu.RUnlock()
	if !ok || idErr != nil || !active {
		log.Tracef("sid [%s] report make hole success: %v, but session not found", m.Sid, m.Success)
		return
	}
	if !hmac.Equal(callerControlID, session.providerControl[:]) && !hmac.Equal(callerControlID, session.visitorControl[:]) {
		return
	}
	if m.Success {
		c.analyzer.ReportSuccess(session.analysisKey, session.recommandMode, session.recommandIndex)
	}
	log.Infof("sid [%s] report make hole success: %v, mode %v, index %v",
		m.Sid, m.Success, session.recommandMode, session.recommandIndex)
}

func (c *Controller) GenNatHoleResponse(transactionID string, session *Session, errInfo string) *msg.NatHoleResp {
	var sid string
	if session != nil {
		sid = session.sid
	}
	return &msg.NatHoleResp{
		TransactionID: transactionID,
		Sid:           sid,
		Error:         errInfo,
	}
}

// analysis analyzes the NAT type and behavior of the visitor and client, then makes hole-punching decisions.
// return the response to the visitor and client.
func (c *Controller) analysis(session *Session) (*msg.NatHoleResp, *msg.NatHoleResp, error) {
	cm := session.clientMsg
	vm := session.visitorMsg

	cNatFeature, err := ClassifyNATFeature(cm.MappedAddrs, parseIPs(cm.AssistedAddrs))
	if err != nil {
		return nil, nil, fmt.Errorf("classify client nat feature error: %v", err)
	}

	vNatFeature, err := ClassifyNATFeature(vm.MappedAddrs, parseIPs(vm.AssistedAddrs))
	if err != nil {
		return nil, nil, fmt.Errorf("classify visitor nat feature error: %v", err)
	}
	session.cNatFeature = cNatFeature
	session.vNatFeature = vNatFeature
	session.genAnalysisKey()

	mode, index, cBehavior, vBehavior := c.analyzer.GetRecommandBehaviors(session.analysisKey, cNatFeature, vNatFeature)
	session.recommandMode = mode
	session.recommandIndex = index
	session.cBehavior = cBehavior
	session.vBehavior = vBehavior

	timeoutMs := max(cBehavior.SendDelayMs, vBehavior.SendDelayMs) + 5000
	if cBehavior.ListenRandomPorts > 0 || vBehavior.ListenRandomPorts > 0 {
		timeoutMs += 30000
	}

	protocol := vm.Protocol
	vResp := newNatHoleResponse(
		vm.TransactionID, session.sid, protocol, mode,
		cm.MappedAddrs, cm.AssistedAddrs, vBehavior,
		timeoutMs-vBehavior.SendDelayMs, cNatFeature.PortsDifference,
	)
	cResp := newNatHoleResponse(
		cm.TransactionID, session.sid, protocol, mode,
		vm.MappedAddrs, vm.AssistedAddrs, cBehavior,
		timeoutMs-cBehavior.SendDelayMs, vNatFeature.PortsDifference,
	)

	manifest := xtcpbinding.Manifest{ProxyName: vm.ProxyName, ProviderControl: session.providerControl, VisitorControl: session.visitorControl, IssuedAt: uint64(time.Now().Unix())}
	manifest.ExpiresAt = manifest.IssuedAt + 60
	sidBytes, err := hex.DecodeString(session.sid)
	if err != nil || len(sidBytes) != 32 {
		return nil, nil, xtcpbinding.ErrBinding
	}
	copy(manifest.SID[:], sidBytes)
	copy(manifest.ProviderNonce[:], cm.Nonce)
	copy(manifest.VisitorNonce[:], vm.Nonce)
	copy(manifest.ProviderSPKI[:], cm.SPKISHA256)
	copy(manifest.VisitorSPKI[:], vm.SPKISHA256)
	manifestWire, err := manifest.Encode()
	if err != nil {
		return nil, nil, err
	}
	vResp.BindingManifest = manifestWire
	cResp.BindingManifest = manifestWire
	vResp.PeerCertificate = cm.Certificate
	cResp.PeerCertificate = vm.Certificate
	log.Debugf("sid [%s] visitor nat: %+v, candidateAddrs: %v; client nat: %+v, candidateAddrs: %v, protocol: %s",
		session.sid, *vNatFeature, vm.MappedAddrs, *cNatFeature, cm.MappedAddrs, protocol)
	log.Debugf("sid [%s] visitor detect behavior: %+v", session.sid, vResp.DetectBehavior)
	log.Debugf("sid [%s] client detect behavior: %+v", session.sid, cResp.DetectBehavior)
	return vResp, cResp, nil
}

func newNatHoleResponse(
	transactionID string,
	sid string,
	protocol string,
	mode int,
	candidateAddrs []string,
	assistedAddrs []string,
	behavior RecommandBehavior,
	readTimeoutMs int,
	portsDifference int,
) *msg.NatHoleResp {
	compactCandidateAddrs := slices.Compact(candidateAddrs)
	compactAssistedAddrs := slices.Compact(assistedAddrs)
	return &msg.NatHoleResp{
		TransactionID:  transactionID,
		Sid:            sid,
		Protocol:       protocol,
		CandidateAddrs: compactCandidateAddrs,
		AssistedAddrs:  compactAssistedAddrs,
		DetectBehavior: msg.NatHoleDetectBehavior{
			Mode:              mode,
			Role:              behavior.Role,
			TTL:               behavior.TTL,
			SendDelayMs:       behavior.SendDelayMs,
			ReadTimeoutMs:     readTimeoutMs,
			SendRandomPorts:   behavior.PortsRandomNumber,
			ListenRandomPorts: behavior.ListenRandomPorts,
			CandidatePorts:    getRangePorts(candidateAddrs, portsDifference, behavior.PortsRangeNumber),
		},
	}
}

func getRangePorts(addrs []string, difference, maxNumber int) []msg.PortsRange {
	if maxNumber <= 0 {
		return nil
	}

	addr, isLast := lo.Last(addrs)
	if !isLast {
		return nil
	}
	ports := make([]msg.PortsRange, 0, 1)
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil
	}
	ports = append(ports, msg.PortsRange{
		From: max(port-difference-5, port-maxNumber, 1),
		To:   min(port+difference+5, port+maxNumber, 65535),
	})
	return ports
}
