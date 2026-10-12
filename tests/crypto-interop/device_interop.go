// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
)

// An explicit software endpoint for one device. It never discovers devices,
// writes firmware, sends serial commands or changes a production FRP service.
type deviceInteropConfig struct {
	ListenIPv4             string   `json:"listen_ipv4"`
	ListenPort             int      `json:"listen_port"`
	DeviceIPv4             string   `json:"device_ipv4"`
	QUICPort               int      `json:"quic_port"`
	Transport              string   `json:"transport"`
	Role                   string   `json:"role"`
	ProxyType              string   `json:"proxy_type"`
	ProxyName              string   `json:"proxy_name"`
	User                   string   `json:"user"`
	ClientID               string   `json:"client_id"`
	Token                  string   `json:"token"`
	SecretKey              string   `json:"secret_key"`
	RemotePort             int      `json:"remote_port"`
	VisitorPort            int      `json:"visitor_port"`
	Domains                []string `json:"custom_domains"`
	VhostPort              int      `json:"vhost_port"`
	BackendPort            int      `json:"backend_port"`
	BackendToken           string   `json:"backend_token"`
	CertificateFile        string   `json:"certificate_file"`
	PrivateKeyFile         string   `json:"private_key_file"`
	CAFile                 string   `json:"ca_file"`
	ServerName             string   `json:"server_name"`
	BackendCertificateFile string   `json:"backend_certificate_file"`
	BackendPrivateKeyFile  string   `json:"backend_private_key_file"`
	BackendCAFile          string   `json:"backend_ca_file"`
	FRPSBinary             string   `json:"frps_binary"`
	FRPCBinary             string   `json:"frpc_binary"`
	FRPSSHA256             string   `json:"frps_sha256"`
	FRPCSHA256             string   `json:"frpc_sha256"`
	STUNPorts              []int    `json:"stun_ports"`
	TimeoutMS              uint32   `json:"timeout_ms"`
	EvidenceDirectory      string   `json:"evidence_directory"`
	configSHA256           string
}

func deviceIPv4(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && ip.To4() != nil && ip.String() == value && (ip.IsGlobalUnicast() || ip.IsLoopback())
}
func devicePort(value int) bool { return value >= 1024 && value <= 65535 }
func deviceJSONFields(data []byte) error {
	allowed := map[string]bool{}
	t := reflect.TypeFor[deviceInteropConfig]()
	for i := 0; i < t.NumField(); i++ {
		if name := t.Field(i).Tag.Get("json"); name != "" {
			allowed[name] = true
		}
	}
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("expected a device interop JSON object")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok || !allowed[key] || seen[key] {
			return fmt.Errorf("unknown, repeated or noncanonical device interop field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return err
		}
	}
	if _, err := d.Token(); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("expected exactly one device interop JSON object")
	}
	return nil
}
func deviceDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c != '-' && !(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') {
				return false
			}
		}
	}
	return true
}
func deviceDigest(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}
func loadDeviceInteropConfig(path string) (deviceInteropConfig, error) {
	var c deviceInteropConfig
	info, err := os.Lstat(path)
	if err != nil {
		return c, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 16384 {
		return c, fmt.Errorf("device interop config requires a private regular file of at most 16384 bytes")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := deviceJSONFields(data); err != nil {
		return c, err
	}
	c.configSHA256 = deviceDigest(data)
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return c, fmt.Errorf("expected one device interop JSON object")
	}
	if !deviceIPv4(c.ListenIPv4) || !deviceIPv4(c.DeviceIPv4) || !devicePort(c.ListenPort) ||
		!slices.Contains([]string{"tcp", "quic"}, c.Transport) || !slices.Contains([]string{"provider", "visitor"}, c.Role) ||
		!slices.Contains([]string{"tcp", "udp", "stcp", "http", "https", "xtcp"}, c.ProxyType) ||
		(c.Role == "visitor" && c.ProxyType != "stcp" && c.ProxyType != "xtcp") ||
		c.TimeoutMS < 1000 || c.TimeoutMS > 300000 || c.Token == "" || len(c.Token) > 1024 ||
		c.ClientID == "" || c.ClientID == "device-interop-peer" || len(c.ClientID) > 128 || len(c.User) > 128 ||
		c.ProxyName == "" || len(c.ProxyName) > 128 || c.ServerName == "" || !filepath.IsAbs(c.EvidenceDirectory) ||
		(c.User != "" && !strings.HasPrefix(c.ProxyName, c.User+".")) {
		return c, fmt.Errorf("invalid explicit endpoint, role, identity, proxy or deadline")
	}
	for _, value := range []string{c.User, c.ClientID, c.ProxyName, c.Token, c.SecretKey, c.BackendToken} {
		if !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return c, fmt.Errorf("identity and secret fields require valid UTF-8 without NUL")
		}
	}
	paths := []string{c.CertificateFile, c.PrivateKeyFile, c.CAFile}
	if c.Transport == "quic" && !devicePort(c.QUICPort) {
		return c, fmt.Errorf("QUIC requires an explicit quic_port")
	}
	if c.Transport == "tcp" && c.QUICPort != 0 {
		return c, fmt.Errorf("TCP fixture must not enable a QUIC endpoint")
	}
	if c.ProxyType == "tcp" || c.ProxyType == "udp" {
		if !devicePort(c.RemotePort) {
			return c, fmt.Errorf("TCP/UDP provider requires remote_port")
		}
	} else if c.RemotePort != 0 {
		return c, fmt.Errorf("remote_port applies only to TCP/UDP")
	}
	if c.Role == "visitor" && !devicePort(c.VisitorPort) {
		return c, fmt.Errorf("device visitor requires visitor_port")
	}
	if c.Role == "provider" && c.VisitorPort != 0 {
		return c, fmt.Errorf("visitor_port applies only to the device visitor")
	}
	if c.ProxyType == "stcp" || c.ProxyType == "xtcp" {
		if c.SecretKey == "" || len(c.SecretKey) > 128 {
			return c, fmt.Errorf("private proxy requires secret_key")
		}
	} else if c.SecretKey != "" {
		return c, fmt.Errorf("secret_key applies only to STCP/XTCP")
	}
	if c.ProxyType == "http" || c.ProxyType == "https" {
		if !devicePort(c.VhostPort) || !devicePort(c.BackendPort) || len(c.Domains) == 0 || len(c.Domains) > 4 || c.BackendToken == "" || len(c.BackendToken) > 1024 {
			return c, fmt.Errorf("HTTP(S) requires domains, vhost/backend ports and backend_token")
		}
		seen := map[string]bool{}
		for _, domain := range c.Domains {
			if !deviceDomain(domain) || seen[strings.ToLower(domain)] {
				return c, fmt.Errorf("expected unique exact custom domains")
			}
			seen[strings.ToLower(domain)] = true
		}
	} else if len(c.Domains) != 0 || c.VhostPort != 0 || c.BackendPort != 0 || c.BackendToken != "" {
		return c, fmt.Errorf("HTTP fields apply only to HTTP/HTTPS")
	}
	if c.ProxyType == "https" {
		paths = append(paths, c.BackendCertificateFile, c.BackendPrivateKeyFile, c.BackendCAFile)
	} else if c.BackendCertificateFile != "" || c.BackendPrivateKeyFile != "" || c.BackendCAFile != "" {
		return c, fmt.Errorf("business TLS files apply only to HTTPS")
	}
	if c.ProxyType == "xtcp" {
		if len(c.STUNPorts) != 2 || c.STUNPorts[0] == c.STUNPorts[1] || !devicePort(c.STUNPorts[0]) || !devicePort(c.STUNPorts[1]) {
			return c, fmt.Errorf("XTCP requires two explicit local STUN ports")
		}
		paths = append(paths, c.FRPSBinary, c.FRPCBinary)
		for _, digest := range []string{c.FRPSSHA256, c.FRPCSHA256} {
			raw, err := hex.DecodeString(digest)
			if err != nil || len(raw) != 32 || strings.ToLower(digest) != digest {
				return c, fmt.Errorf("XTCP requires exact lowercase FRPS/FRPC SHA256 values")
			}
		}
	} else if c.FRPSBinary != "" || c.FRPCBinary != "" || c.FRPSSHA256 != "" || c.FRPCSHA256 != "" || len(c.STUNPorts) != 0 {
		return c, fmt.Errorf("maintained binaries and STUN endpoints apply only to XTCP")
	}
	for _, path := range paths {
		if !filepath.IsAbs(path) {
			return c, fmt.Errorf("certificate, CA and binary paths must be absolute")
		}
	}
	ports := []int{c.ListenPort, c.RemotePort, c.VhostPort, c.BackendPort}
	for i, port := range ports {
		if port != 0 && slices.Contains(ports[:i], port) {
			return c, fmt.Errorf("TCP fixture ports must be distinct")
		}
	}
	return c, nil
}

type deviceAdmission struct{ loggedIn, registered atomic.Bool }

func deviceAdmissionPlugin(c deviceInteropConfig) (*httptest.Server, *deviceAdmission) {
	state := &deviceAdmission{}
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Op      string          `json:"op"`
			Content json.RawMessage `json:"content"`
		}
		err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&request)
		accepted := false
		if err == nil && request.Op == "Login" {
			var login plugin.LoginContent
			if json.Unmarshal(request.Content, &login) == nil {
				host, _, splitErr := net.SplitHostPort(login.ClientAddress)
				device := splitErr == nil && host == c.DeviceIPv4 && login.ClientID == c.ClientID && login.User == c.User
				desktop := splitErr == nil && host == c.ListenIPv4 && login.ClientID == "device-interop-peer" && login.User == c.User
				accepted = device || desktop
				if device {
					state.loggedIn.Store(true)
				}
			}
		} else if err == nil && request.Op == "NewProxy" {
			var proxy plugin.NewProxyContent
			if json.Unmarshal(request.Content, &proxy) == nil {
				p := proxy.NewProxy
				var users []string
				if c.Role == "visitor" && (c.ProxyType == "stcp" || c.ProxyType == "xtcp") {
					users = []string{c.User}
				}
				accepted = proxy.User.User == c.User && p.ProxyName == c.ProxyName && p.ProxyType == c.ProxyType &&
					!p.UseEncryption && !p.UseCompression && p.RemotePort == c.RemotePort &&
					slices.Equal(p.CustomDomains, c.Domains) && p.SubDomain == "" && p.Sk == c.SecretKey && slices.Equal(p.AllowUsers, users) &&
					p.Group == "" && p.GroupKey == "" && len(p.Locations) == 0 && p.HTTPUser == "" && p.HTTPPwd == "" && p.HostHeaderRewrite == "" &&
					len(p.Headers) == 0 && len(p.ResponseHeaders) == 0 && p.RouteByHTTPUser == "" && p.Multiplexer == ""
				if accepted {
					state.registered.Store(true)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(plugin.Response{Reject: !accepted, RejectReason: "explicit device fixture admission rejected", Unchange: true})
	}))
	return service, state
}

func deviceWriteJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

type deviceInteropReport struct {
	Status              string   `json:"status"`
	ConfigurationSHA256 string   `json:"configuration_sha256"`
	Counterpart         string   `json:"counterpart"`
	FRPSSHA256          string   `json:"frps_sha256,omitempty"`
	FRPCSHA256          string   `json:"frpc_sha256,omitempty"`
	Role                string   `json:"role"`
	ProxyType           string   `json:"proxy_type"`
	Transport           string   `json:"transport"`
	PassedScope         []string `json:"passed_scope"`
	NetworkScope        string   `json:"network_scope"`
}

func deviceVerifiedBinary(path, expected, destination string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
		return "", fmt.Errorf("maintained binary must be an executable regular file, without symlinks")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !os.SameFile(info, opened) {
		return "", fmt.Errorf("maintained binary changed while opening")
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}
	digest := deviceDigest(data)
	if digest != expected {
		return "", fmt.Errorf("maintained binary SHA256 mismatch")
	}
	if err := os.WriteFile(destination, data, 0700); err != nil {
		return "", err
	}
	return digest, nil
}
func deviceProcess(ctx context.Context, binary, configPath, logPath, ready string) (func(), error) {
	output, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	command := exec.CommandContext(ctx, binary, "-c", configPath)
	command.Stdout, command.Stderr = output, output
	if err = command.Start(); err != nil {
		_ = output.Close()
		return nil, err
	}
	done := make(chan struct{})
	go func() { _ = command.Wait(); _ = output.Close(); close(done) }()
	stop := func() { _ = command.Process.Kill(); <-done }
	if ready == "" {
		return stop, nil
	}
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return nil, fmt.Errorf("FRP fixture process exited before readiness; inspect private log")
		case <-ctx.Done():
			stop()
			return nil, ctx.Err()
		case <-deadline.C:
			stop()
			return nil, fmt.Errorf("FRP fixture process readiness timeout; inspect private log")
		case <-ticker.C:
			logs, err := os.ReadFile(logPath)
			if err != nil {
				stop()
				return nil, err
			}
			if bytes.Contains(logs, []byte(ready)) {
				return stop, nil
			}
		}
	}
}
func deviceServer(ctx context.Context, c deviceInteropConfig, dir, pluginAddress string) (func(), error) {
	config := &v1.ServerConfig{BindAddr: c.ListenIPv4, BindPort: c.ListenPort, QUICBindPort: c.QUICPort,
		ProxyBindAddr: c.ListenIPv4, UDPPacketSize: 1500,
		HTTPPlugins: []v1.HTTPPluginOptions{{Name: "device-admission", Addr: pluginAddress, Ops: []string{"Login", "NewProxy"}}}}
	if c.ProxyType == "http" {
		config.VhostHTTPPort = c.VhostPort
	}
	if c.ProxyType == "https" {
		config.VhostHTTPSPort = c.VhostPort
	}
	config.Auth.Token = c.Token
	config.Auth.AdditionalScopes = []v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}
	config.Transport.TLS.Force = true
	config.Transport.TLS.CertFile, config.Transport.TLS.KeyFile = c.CertificateFile, c.PrivateKeyFile
	config.Log.To, config.Log.Level, config.Log.DisablePrintColor = "console", "info", true
	if err := config.Complete(); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "frps.json")
	if err := deviceWriteJSON(path, config); err != nil {
		return nil, err
	}
	return deviceProcess(ctx, c.FRPSBinary, path, filepath.Join(dir, "frps.log"), "frps started successfully")
}

func deviceHostClient(ctx context.Context, c deviceInteropConfig, dir string, backendPort, visitorPort int) (func(), error) {
	common := &v1.ClientCommonConfig{ServerAddr: c.ListenIPv4, ServerPort: c.ListenPort, User: c.User, ClientID: "device-interop-peer"}
	common.Auth.Token = c.Token
	common.Auth.AdditionalScopes = []v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}
	common.Transport.WireProtocol = "v2"
	common.Transport.TLS.ServerName, common.Transport.TLS.TrustedCaFile = c.ServerName, c.CAFile
	if c.Transport == "quic" {
		common.Transport.Protocol, common.ServerPort = "quic", c.QUICPort
	}
	name := c.ProxyName
	if c.User != "" {
		name = strings.TrimPrefix(name, c.User+".")
	}
	var proxies []v1.ProxyConfigurer
	var visitors []v1.VisitorConfigurer
	if c.Role == "visitor" {
		base := v1.ProxyBaseConfig{Name: name, Type: c.ProxyType, ProxyBackend: v1.ProxyBackend{LocalIP: "127.0.0.1", LocalPort: backendPort}}
		if c.ProxyType == "stcp" {
			proxies = []v1.ProxyConfigurer{&v1.STCPProxyConfig{ProxyBaseConfig: base, Secretkey: c.SecretKey, AllowUsers: []string{c.User}}}
		} else {
			proxies = []v1.ProxyConfigurer{&v1.XTCPProxyConfig{ProxyBaseConfig: base, Secretkey: c.SecretKey, AllowUsers: []string{c.User}}}
		}
	} else {
		base := v1.VisitorBaseConfig{Name: "device-interop-visitor", Type: c.ProxyType, ServerUser: c.User, ServerName: name,
			SecretKey: c.SecretKey, BindAddr: "127.0.0.1", BindPort: visitorPort}
		if c.ProxyType == "stcp" {
			visitors = []v1.VisitorConfigurer{&v1.STCPVisitorConfig{VisitorBaseConfig: base}}
		} else {
			visitors = []v1.VisitorConfigurer{&v1.XTCPVisitorConfig{VisitorBaseConfig: base, Protocol: "quic"}}
		}
	}
	if c.ProxyType == "xtcp" {
		common.NatHoleSTUNServer = net.JoinHostPort(c.ListenIPv4, strconv.Itoa(c.STUNPorts[0]))
	}
	common.Log.To, common.Log.Level, common.Log.DisablePrintColor = "console", "info", true
	path := filepath.Join(dir, "frpc.json")
	config := struct {
		*v1.ClientCommonConfig
		Proxies  []v1.ProxyConfigurer   `json:"proxies,omitempty"`
		Visitors []v1.VisitorConfigurer `json:"visitors,omitempty"`
	}{common, proxies, visitors}
	if err := deviceWriteJSON(path, config); err != nil {
		return nil, err
	}
	return deviceProcess(ctx, c.FRPCBinary, path, filepath.Join(dir, "frpc.log"), "login to server success")
}

func deviceTCPBackend() (int, func(), error) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return 0, nil, err
	}
	var workers sync.WaitGroup
	var connections sync.Map
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			connections.Store(conn, true)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				defer connections.Delete(conn)
				_, _ = io.Copy(conn, conn)
				_ = conn.CloseWrite()
			}()
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, func() {
		_ = listener.Close()
		<-done
		connections.Range(func(key, value any) bool { _ = key.(*net.TCPConn).Close(); return true })
		workers.Wait()
	}, nil
}

// The fixture provides two standard STUN binding responders on the explicitly
// selected host, for LAN discovery only. It does not simulate external NAT.
func deviceSTUN(c deviceInteropConfig) (func(), error) {
	var sockets []*net.UDPConn
	for _, port := range c.STUNPorts {
		socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(c.ListenIPv4), Port: port})
		if err != nil {
			for _, socket := range sockets {
				_ = socket.Close()
			}
			return nil, err
		}
		sockets = append(sockets, socket)
	}
	var workers sync.WaitGroup
	for i, socket := range sockets {
		other := sockets[1-i].LocalAddr().(*net.UDPAddr)
		workers.Add(1)
		go func() {
			defer workers.Done()
			var packet [1024]byte
			for {
				n, from, err := socket.ReadFromUDP(packet[:])
				if err != nil {
					return
				}
				if n < 20 || binary.BigEndian.Uint16(packet[:2]) != 1 || binary.BigEndian.Uint32(packet[4:8]) != 0x2112a442 {
					continue
				}
				response := make([]byte, 44)
				binary.BigEndian.PutUint16(response[:2], 0x0101)
				binary.BigEndian.PutUint16(response[2:4], 24)
				copy(response[4:20], packet[4:20])
				binary.BigEndian.PutUint16(response[20:22], 0x0020)
				binary.BigEndian.PutUint16(response[22:24], 8)
				response[25] = 1
				binary.BigEndian.PutUint16(response[26:28], uint16(from.Port)^0x2112)
				cookie := []byte{0x21, 0x12, 0xa4, 0x42}
				for j, value := range from.IP.To4() {
					response[28+j] = value ^ cookie[j]
				}
				binary.BigEndian.PutUint16(response[32:34], 0x802c)
				binary.BigEndian.PutUint16(response[34:36], 8)
				response[37] = 1
				binary.BigEndian.PutUint16(response[38:40], uint16(other.Port))
				copy(response[40:44], other.IP.To4())
				_, _ = socket.WriteToUDP(response, from)
			}
		}()
	}
	return func() {
		for _, socket := range sockets {
			_ = socket.Close()
		}
		workers.Wait()
	}, nil
}

type deviceHTTPStats struct{ authorized, accepted, requests atomic.Uint64 }

func deviceHTTPBackend(ctx context.Context, c deviceInteropConfig) (func(), *deviceHTTPStats, error) {
	stats := &deviceHTTPStats{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stats.requests.Add(1)
		validHost := slices.ContainsFunc(c.Domains, func(domain string) bool { return strings.EqualFold(domain, r.Host) })
		if !validHost || (c.ProxyType == "https" && (r.TLS == nil || !strings.EqualFold(r.TLS.ServerName, r.Host))) {
			http.Error(w, "wrong Host/SNI", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+c.BackendToken {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		id, err := strconv.ParseUint(r.URL.Query().Get("id"), 10, 32)
		if err != nil || r.Method != http.MethodGet || r.URL.Path != "/body" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		payload := workPattern(uint32(id), true)
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
		stats.authorized.Add(1)
		_, _ = w.Write(payload)
	})
	var certificate tls.Certificate
	if c.ProxyType == "https" {
		var err error
		certificate, err = tls.LoadX509KeyPair(c.BackendCertificateFile, c.BackendPrivateKeyFile)
		if err != nil {
			return nil, nil, err
		}
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP(c.ListenIPv4), Port: c.BackendPort})
	if err != nil {
		return nil, nil, err
	}
	var workers sync.WaitGroup
	var connections sync.Map
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			raw, err := listener.AcceptTCP()
			if err != nil {
				return
			}
			stats.accepted.Add(1)
			connections.Store(raw, true)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer raw.Close()
				defer connections.Delete(raw)
				deadline := time.Now().Add(10 * time.Second)
				if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
					deadline = end
				}
				_ = raw.SetDeadline(deadline)
				var conn net.Conn = raw
				var secured *tls.Conn
				if c.ProxyType == "https" {
					secured = tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
					if err := secured.HandshakeContext(ctx); err != nil {
						return
					}
					conn = secured
				}
				request, err := http.ReadRequest(bufio.NewReader(conn))
				if err != nil {
					return
				}
				defer request.Body.Close()
				if secured != nil {
					state := secured.ConnectionState()
					request.TLS = &state
				}
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, request)
				response := recorder.Result()
				defer response.Body.Close()
				response.Close = true
				response.ContentLength = int64(recorder.Body.Len())
				if err := response.Write(conn); err != nil {
					return
				}
				if secured != nil {
					if err := secured.CloseWrite(); err != nil {
						return
					}
				}
				if err := raw.CloseWrite(); err != nil {
					return
				}
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return func() {
		_ = listener.Close()
		<-done
		connections.Range(func(key, value any) bool { _ = key.(*net.TCPConn).Close(); return true })
		workers.Wait()
	}, stats, nil
}

func deviceEcho(ctx context.Context, address string, id uint32) error {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	payload := workPattern(id, false)
	for offset := 0; offset < len(payload); {
		n := min(1024, len(payload)-offset)
		part := payload[offset : offset+n]
		if _, err = io.CopyN(conn, bytes.NewReader(part), int64(n)); err != nil {
			return err
		}
		got := make([]byte, n)
		if _, err = io.ReadFull(conn, got); err != nil {
			return err
		}
		if !bytes.Equal(got, part) {
			return fmt.Errorf("device echo byte mismatch")
		}
		offset += n
	}
	if err = conn.(*net.TCPConn).CloseWrite(); err != nil {
		return err
	}
	var tail [1]byte
	n, err := conn.Read(tail[:])
	if n != 0 || err != io.EOF {
		return fmt.Errorf("device echo FIN: bytes=%d error=%v", n, err)
	}
	return nil
}
func deviceUDPEcho(ctx context.Context, address string) error {
	target, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		return err
	}
	for source := 0; source < 2; source++ {
		conn, err := net.DialUDP("udp4", nil, target)
		if err != nil {
			return err
		}
		defer conn.Close()
		for _, size := range []int{0, 1, 127, 1024, 1500} {
			payload := bytes.Repeat([]byte{byte(0x30 + source)}, size)
			deadline := time.Now().Add(8 * time.Second)
			if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
				deadline = end
			}
			_ = conn.SetDeadline(deadline)
			if _, err = conn.Write(payload); err != nil {
				return err
			}
			var buffer [1501]byte
			n, err := conn.Read(buffer[:])
			if err != nil {
				return err
			}
			if !bytes.Equal(buffer[:n], payload) {
				return fmt.Errorf("device UDP datagram boundary/content mismatch")
			}
		}
	}
	return nil
}
func deviceHTTPProbe(ctx context.Context, c deviceInteropConfig, stats *deviceHTTPStats) error {
	var roots *x509.CertPool
	if c.ProxyType == "https" {
		data, err := os.ReadFile(c.BackendCAFile)
		if err != nil {
			return err
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(data) {
			return fmt.Errorf("invalid backend CA")
		}
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp4", net.JoinHostPort(c.ListenIPv4, strconv.Itoa(c.VhostPort)))
		}}
	defer transport.CloseIdleConnections()
	requester := &http.Client{Transport: transport}
	request := func(host string, id uint32, token bool) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.ProxyType+"://"+host+"/body?id="+strconv.FormatUint(uint64(id), 10), nil)
		if err != nil {
			return err
		}
		if token {
			req.Header.Set("Authorization", "Bearer "+c.BackendToken)
		}
		response, err := requester.Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 300002))
		if err != nil {
			return err
		}
		if !token {
			if response.StatusCode != http.StatusUnauthorized {
				return fmt.Errorf("missing Bearer requires status 401, got %d", response.StatusCode)
			}
			return nil
		}
		if response.StatusCode != http.StatusOK || !bytes.Equal(body, workPattern(id, true)) {
			return fmt.Errorf("device %s response status=%d bytes=%d", c.ProxyType, response.StatusCode, len(body))
		}
		return nil
	}
	for i, host := range c.Domains {
		if err := request(host, uint32(i), true); err != nil {
			return err
		}
	}
	beforeAuthorized := stats.authorized.Load()
	if err := request(c.Domains[0], 99, false); err != nil {
		return err
	}
	if stats.authorized.Load() != beforeAuthorized {
		return fmt.Errorf("missing Bearer reached authorized business response")
	}
	beforeAccepted, beforeRequests := stats.accepted.Load(), stats.requests.Load()
	if err := request("absent.device-interop.invalid", 100, true); err == nil {
		return fmt.Errorf("unregistered Host/SNI accepted")
	}
	if stats.accepted.Load() != beforeAccepted || stats.requests.Load() != beforeRequests {
		return fmt.Errorf("unregistered route reached business backend")
	}
	return nil
}

func runDeviceInterop(path string) (runErr error) {
	c, err := loadDeviceInteropConfig(path)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, deadlineCancel := context.WithTimeout(ctx, time.Duration(c.TimeoutMS)*time.Millisecond)
	defer deadlineCancel()
	dir := c.EvidenceDirectory
	if err := os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("evidence directory must be new: %w", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if deviceDigest(data) != c.configSHA256 {
		return fmt.Errorf("device input changed while opening")
	}
	if err := os.WriteFile(filepath.Join(dir, "input.json"), data, 0600); err != nil {
		return err
	}
	report := deviceInteropReport{Status: "failed", ConfigurationSHA256: c.configSHA256, Counterpart: "official_frp_v0.71.0", Role: c.Role, ProxyType: c.ProxyType, Transport: c.Transport,
		PassedScope: []string{}, NetworkScope: "explicit_ipv4_business_only"}
	var stops []func()
	defer func() {
		cancel()
		for i := len(stops) - 1; i >= 0; i-- {
			stops[i]()
		}
		if runErr == nil {
			report.Status = "passed"
		} else {
			report.PassedScope = []string{}
		}
		encoded, err := json.MarshalIndent(report, "", "  ")
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, "result.json"), append(encoded, '\n'), 0600)
		}
		if runErr == nil && err != nil {
			runErr = err
		}
		if runErr == nil {
			fmt.Printf("ESP_FRP_DEVICE_INTEROP_FINISHED role=%s type=%s transport=%s\n", c.Role, c.ProxyType, c.Transport)
		}
	}()
	if c.ProxyType == "xtcp" {
		report.Counterpart, report.NetworkScope = "maintained_xtcp_candidate_inputs", "lan_local_stun_only_no_external_nat_claim"
		serverBinary, clientBinary := filepath.Join(dir, "frps"), filepath.Join(dir, "frpc")
		if report.FRPSSHA256, err = deviceVerifiedBinary(c.FRPSBinary, c.FRPSSHA256, serverBinary); err != nil {
			return err
		}
		if report.FRPCSHA256, err = deviceVerifiedBinary(c.FRPCBinary, c.FRPCSHA256, clientBinary); err != nil {
			return err
		}
		c.FRPSBinary, c.FRPCBinary = serverBinary, clientBinary
	} else {
		build := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-mod=readonly", "-tags=noweb", "-o", dir+string(os.PathSeparator), "github.com/fatedier/frp/cmd/frps", "github.com/fatedier/frp/cmd/frpc")
		if output, err := build.CombinedOutput(); err != nil {
			return fmt.Errorf("build fixed official FRP executables: %w: %s", err, output)
		}
		c.FRPSBinary, c.FRPCBinary = filepath.Join(dir, "frps"), filepath.Join(dir, "frpc")
		serverData, err := os.ReadFile(c.FRPSBinary)
		if err != nil {
			return err
		}
		report.FRPSSHA256 = deviceDigest(serverData)
		clientData, err := os.ReadFile(c.FRPCBinary)
		if err != nil {
			return err
		}
		report.FRPCSHA256 = deviceDigest(clientData)
	}
	admission, state := deviceAdmissionPlugin(c)
	stops = append(stops, admission.Close)
	if c.ProxyType == "xtcp" {
		stop, err := deviceSTUN(c)
		if err != nil {
			return err
		}
		stops = append(stops, stop)
	}
	var stats *deviceHTTPStats
	if c.ProxyType == "http" || c.ProxyType == "https" {
		stop, count, err := deviceHTTPBackend(ctx, c)
		if err != nil {
			return err
		}
		stops = append(stops, stop)
		stats = count
	}
	stopServer, err := deviceServer(ctx, c, dir, strings.TrimPrefix(admission.URL, "http://"))
	if err != nil {
		return err
	}
	stops = append(stops, stopServer)
	backendPort, hostVisitorPort := 0, 0
	if c.Role == "visitor" {
		port, stop, err := deviceTCPBackend()
		if err != nil {
			return err
		}
		stops = append(stops, stop)
		backendPort = port
	}
	if c.Role == "provider" && (c.ProxyType == "stcp" || c.ProxyType == "xtcp") {
		hostVisitorPort = visitorFreePort()
	}
	if c.Role == "visitor" || c.ProxyType == "stcp" || c.ProxyType == "xtcp" {
		stop, err := deviceHostClient(ctx, c, dir, backendPort, hostVisitorPort)
		if err != nil {
			return err
		}
		stops = append(stops, stop)
	}
	fmt.Printf("ESP_FRP_DEVICE_INTEROP_READY role=%s type=%s transport=%s\n", c.Role, c.ProxyType, c.Transport)
	if err := waitDeviceResume(ctx); err != nil {
		return err
	}
	if !state.loggedIn.Load() || !state.registered.Load() {
		return fmt.Errorf("resume requires the exact device Login and expected proxy registration")
	}
	address := net.JoinHostPort(c.ListenIPv4, strconv.Itoa(c.RemotePort))
	if c.Role == "visitor" {
		address = net.JoinHostPort(c.DeviceIPv4, strconv.Itoa(c.VisitorPort))
	} else if hostVisitorPort != 0 {
		address = net.JoinHostPort("127.0.0.1", strconv.Itoa(hostVisitorPort))
	}
	if c.ProxyType == "udp" {
		err = deviceUDPEcho(ctx, address)
	} else if c.ProxyType == "http" || c.ProxyType == "https" {
		err = deviceHTTPProbe(ctx, c, stats)
	} else {
		results := make(chan error, 2)
		for id := uint32(0); id < 2; id++ {
			go func() { results <- deviceEcho(ctx, address, id) }()
		}
		for range 2 {
			if failure := <-results; failure != nil && err == nil {
				err = failure
			}
		}
	}
	if err != nil {
		return err
	}
	if c.ProxyType == "udp" {
		report.PassedScope = []string{"two_sources_exact_datagrams_0_1_127_1024_1500_bytes"}
	} else if c.ProxyType == "http" || c.ProxyType == "https" {
		report.PassedScope = []string{"registered_domains_each_exact_300001_byte_body", "backend_bearer_authorization_401", "unregistered_host_or_sni_rejected"}
	} else {
		report.PassedScope = []string{"two_concurrent_exact_300001_byte_echo_streams", "both_streams_remote_fin_and_empty_tail"}
	}
	return nil
}
