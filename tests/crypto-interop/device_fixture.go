// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/hashicorp/yamux"
)

// One explicit peer and one case. No device discovery, firmware writing,
// production service configuration, proxy listener or remote control API.
type deviceFixtureConfig struct {
	ListenIPv4      string `json:"listen_ipv4"`
	ListenPort      int    `json:"listen_port"`
	AllowedPeerIPv4 string `json:"allowed_peer_ipv4"`
	CertificateFile string `json:"certificate_file"`
	PrivateKeyFile  string `json:"private_key_file"`
	Mode            string `json:"mode"`
	Token           string `json:"token"`
	ClientID        string `json:"client_id"`
	ProxyName       string `json:"proxy_name"`
	TimeoutMS       uint32 `json:"timeout_ms"`
}

var deviceWorkModes = []string{"work-wrong-name", "work-error", "work-oversized", "work-truncated",
	"work-bad-port", "work-duplicate", "work-frame-timeout", "work-idle"}

func loadDeviceFixtureConfig(path string) (deviceFixtureConfig, error) {
	var c deviceFixtureConfig
	info, err := os.Lstat(path)
	if err != nil {
		return c, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16384 {
		return c, fmt.Errorf("device fixture config must be a private regular file of at most 16384 bytes")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return c, fmt.Errorf("device fixture config must contain one JSON object")
	}
	for _, value := range []string{c.ListenIPv4, c.AllowedPeerIPv4} {
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil || ip.String() != value || (!ip.IsGlobalUnicast() && !ip.IsLoopback()) {
			return c, fmt.Errorf("device fixture requires explicit unicast IPv4 endpoints")
		}
	}
	if c.ListenPort < 1024 || c.ListenPort > 65535 || c.TimeoutMS < 1000 || c.TimeoutMS > 90000 ||
		c.Token == "" || len(c.Token) > 1024 || c.ClientID == "" || len(c.ClientID) > 128 ||
		c.ProxyName == "" || len(c.ProxyName) > 128 || !filepath.IsAbs(c.CertificateFile) || !filepath.IsAbs(c.PrivateKeyFile) {
		return c, fmt.Errorf("invalid device fixture endpoint, identity, file path or deadline")
	}
	if !slices.Contains(sessionFixtureModes, c.Mode) && !slices.Contains(deviceWorkModes, c.Mode) {
		return c, fmt.Errorf("unsupported device fixture mode")
	}
	return c, nil
}

func runDeviceFixture(path string) error {
	c, err := loadDeviceFixtureConfig(path)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(c.CertificateFile, c.PrivateKeyFile)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(c.ListenIPv4), Port: c.ListenPort})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = listener.SetDeadline(time.Now().Add(time.Duration(c.TimeoutMS) * time.Millisecond)); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	fmt.Printf("ESP_FRP_DEVICE_FIXTURE_READY mode=%s\n", c.Mode)
	raw, err := listener.AcceptTCP()
	if err != nil {
		return err
	}
	defer raw.Close()
	if !raw.RemoteAddr().(*net.TCPAddr).IP.Equal(net.ParseIP(c.AllowedPeerIPv4)) {
		return fmt.Errorf("device fixture refused an unexpected peer")
	}
	go func() { <-ctx.Done(); _ = raw.Close() }()
	var work func(*yamux.Session, *msg.V2ReadWriter, string) error
	if slices.Contains(deviceWorkModes, c.Mode) {
		work = func(m *yamux.Session, control *msg.V2ReadWriter, proxy string) error {
			result := make(chan error, 1)
			done := make(chan struct{})
			defer close(done)
			go func() {
				select {
				case err := <-result:
					if err == nil {
						fmt.Printf("ESP_FRP_DEVICE_WORK_REJECTED mode=%s\n", c.Mode)
					}
				case <-done:
				}
			}()
			return workFixtureProtocol(m, control, proxy, c.Mode, c.Token, nil, result)
		}
	}
	err = serveSessionFixture(raw, cert, sessionFixtureOptions{mode: c.Mode, token: c.Token,
		clientID: c.ClientID, proxyName: c.ProxyName, timeout: time.Duration(c.TimeoutMS) * time.Millisecond}, work)
	if err == nil {
		fmt.Printf("ESP_FRP_DEVICE_FIXTURE_FINISHED mode=%s\n", c.Mode)
	}
	return err
}
