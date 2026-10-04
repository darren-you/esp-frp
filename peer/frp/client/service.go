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

package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatedier/golib/crypto"
	"github.com/samber/lo"

	"github.com/fatedier/frp/client/proxy"
	"github.com/fatedier/frp/pkg/auth"
	"github.com/fatedier/frp/pkg/config"
	"github.com/fatedier/frp/pkg/config/source"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/policy/security"
	httppkg "github.com/fatedier/frp/pkg/util/http"
	"github.com/fatedier/frp/pkg/util/log"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/wait"
	"github.com/fatedier/frp/pkg/util/xlog"
	"github.com/fatedier/frp/pkg/vnet"
)

func init() {
	crypto.DefaultSalt = "frp"
	// Disable quic-go's receive buffer warning.
	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")
	// Disable quic-go's ECN support by default. It may cause issues on certain operating systems.
	if os.Getenv("QUIC_GO_DISABLE_ECN") == "" {
		os.Setenv("QUIC_GO_DISABLE_ECN", "true")
	}
}

type cancelErr struct {
	Err error
}

func (e cancelErr) Error() string {
	return e.Err.Error()
}

// ServiceOptions contains options for creating a new client service.
type ServiceOptions struct {
	Common *v1.ClientCommonConfig

	// ConfigSourceAggregator manages internal config and optional store sources.
	// It is required for creating a Service.
	ConfigSourceAggregator *source.Aggregator

	UnsafeFeatures *security.UnsafeFeatures

	// ConfigFilePath is the path to the configuration file used to initialize.
	// If it is empty, it means that the configuration file is not used for initialization.
	// It may be initialized using command line parameters or called directly.
	ConfigFilePath string

	// ClientSpec is the client specification that control the client behavior.
	ClientSpec *msg.ClientSpec

	// ConnectorCreator is a function that creates a new connector to make connections to the server.
	// The Connector shields the underlying connection details, whether it is through TCP or QUIC connection,
	// and regardless of whether multiplexing is used.
	//
	// If it is not set, the default frpc connector will be used.
	// By using a custom Connector, it can be used to implement a VirtualClient, which connects to frps
	// through a pipe instead of a real physical connection.
	ConnectorCreator func(context.Context, *v1.ClientCommonConfig) Connector

	// HandleWorkConnCb is a callback function that is called when a new work connection is created.
	//
	// If it is not set, the default frpc implementation will be used.
	HandleWorkConnCb func(*v1.ProxyBaseConfig, net.Conn, *msg.StartWorkConn) bool
}

// setServiceOptionsDefault sets the default values for ServiceOptions.
func setServiceOptionsDefault(options *ServiceOptions) error {
	if options.Common != nil {
		if err := options.Common.Complete(); err != nil {
			return err
		}
	}
	if options.ConnectorCreator == nil {
		options.ConnectorCreator = NewConnector
	}
	return nil
}

// Service is the client service that connects to frps and provides proxy services.
type Service struct {
	ctlMu sync.RWMutex
	// Stores gracefulShutdownDuration independently from ctlMu, because the
	// graceful shutdown wait may hold ctlMu for an arbitrary duration.
	gracefulShutdownDuration atomic.Int64
	// manager control connection with server
	ctl *Control
	// Uniq id got from frps, it will be attached to loginMsg.
	runID string

	// Auth runtime and encryption materials
	auth *auth.ClientAuth

	// web server for admin UI and apis
	webServer *httppkg.Server

	vnetController *vnet.Controller

	cfgMu sync.RWMutex
	// reloadMu serializes reload transactions to keep reloadCommon and applied
	// config in sync across concurrent API operations.
	reloadMu sync.Mutex
	common   *v1.ClientCommonConfig
	// reloadCommon is used for filtering/defaulting during config-source reloads.
	// It can be updated by /api/reload without mutating startup-only common behavior.
	reloadCommon *v1.ClientCommonConfig
	proxyCfgs    []v1.ProxyConfigurer
	visitorCfgs  []v1.VisitorConfigurer
	clientSpec   *msg.ClientSpec

	// aggregator manages multiple configuration sources.
	// When set, the service watches for config changes and reloads automatically.
	aggregator   *source.Aggregator
	configSource *source.ConfigSource
	storeSource  *source.StoreSource

	unsafeFeatures *security.UnsafeFeatures

	// The configuration file used to initialize this client, or an empty
	// string if no configuration file was used.
	configFilePath string

	// service context
	ctx context.Context
	// call cancel to stop service
	cancel context.CancelCauseFunc

	connectorCreator func(context.Context, *v1.ClientCommonConfig) Connector
	handleWorkConnCb func(*v1.ProxyBaseConfig, net.Conn, *msg.StartWorkConn) bool
}

func NewService(options ServiceOptions) (*Service, error) {
	if err := setServiceOptionsDefault(&options); err != nil {
		return nil, err
	}

	authRuntime, err := auth.BuildClientAuth(&options.Common.Auth)
	if err != nil {
		return nil, err
	}

	if options.ConfigSourceAggregator == nil {
		return nil, fmt.Errorf("config source aggregator is required")
	}

	configSource := options.ConfigSourceAggregator.ConfigSource()
	storeSource := options.ConfigSourceAggregator.StoreSource()

	proxyCfgs, visitorCfgs, loadErr := options.ConfigSourceAggregator.Load()
	if loadErr != nil {
		return nil, fmt.Errorf("failed to load config from aggregator: %w", loadErr)
	}
	proxyCfgs, visitorCfgs = config.FilterClientConfigurers(options.Common, proxyCfgs, visitorCfgs)
	proxyCfgs = config.CompleteProxyConfigurers(proxyCfgs)
	visitorCfgs = config.CompleteVisitorConfigurers(visitorCfgs)
	if configsNeedXTCPBinding(proxyCfgs, visitorCfgs) && !canRequestXTCPBinding(options.Common, authRuntime, options.ClientSpec) {
		return nil, fmt.Errorf("XTCP requires verified TLS, Token authentication and v2 control")
	}

	// Create the web server after all fallible steps so its listener is not
	// leaked when an earlier error causes NewService to return.
	var webServer *httppkg.Server
	if options.Common.WebServer.Port > 0 {
		ws, err := httppkg.NewServer(options.Common.WebServer)
		if err != nil {
			return nil, err
		}
		webServer = ws
	}

	s := &Service{
		ctx:              context.Background(),
		auth:             authRuntime,
		webServer:        webServer,
		common:           options.Common,
		reloadCommon:     options.Common,
		configFilePath:   options.ConfigFilePath,
		unsafeFeatures:   options.UnsafeFeatures,
		proxyCfgs:        proxyCfgs,
		visitorCfgs:      visitorCfgs,
		clientSpec:       options.ClientSpec,
		aggregator:       options.ConfigSourceAggregator,
		configSource:     configSource,
		storeSource:      storeSource,
		connectorCreator: options.ConnectorCreator,
		handleWorkConnCb: options.HandleWorkConnCb,
	}

	if webServer != nil {
		webServer.RouteRegister(s.registerRouteHandlers)
	}
	if options.Common.VirtualNet.Address != "" {
		s.vnetController = vnet.NewController(options.Common.VirtualNet)
	}
	return s, nil
}

func (svr *Service) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancelCause(ctx)
	svr.ctx = xlog.NewContext(ctx, xlog.FromContextSafe(ctx))
	svr.cancel = cancel

	// set custom DNSServer
	if svr.common.DNSServer != "" {
		netpkg.SetDefaultDNSAddress(svr.common.DNSServer)
	}

	if svr.vnetController != nil {
		vnetController := svr.vnetController
		if err := svr.vnetController.Init(); err != nil {
			log.Errorf("init virtual network controller error: %v", err)
			svr.stop()
			return err
		}
		go func() {
			log.Infof("virtual network controller start...")
			if err := vnetController.Run(); err != nil && !errors.Is(err, net.ErrClosed) {
				log.Warnf("virtual network controller exit with error: %v", err)
			}
		}()
	}

	if svr.webServer != nil {
		webServer := svr.webServer
		go func() {
			log.Infof("admin server listen on %s", webServer.Address())
			if err := webServer.Run(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Warnf("admin server exit with error: %v", err)
			}
		}()
	}

	// first login to frps
	svr.loopLoginUntilSuccess(10*time.Second, lo.FromPtr(svr.common.LoginFailExit))
	if svr.currentControl() == nil {
		cancelCause := cancelErr{}
		_ = errors.As(context.Cause(svr.ctx), &cancelCause)
		svr.stop()
		return fmt.Errorf("login to the server failed: %v. With loginFailExit enabled, no additional retries will be attempted", cancelCause.Err)
	}

	go svr.keepControllerWorking()

	<-svr.ctx.Done()
	svr.stop()
	return nil
}

func (svr *Service) currentControl() *Control {
	svr.ctlMu.RLock()
	defer svr.ctlMu.RUnlock()
	return svr.ctl
}

func (svr *Service) keepControllerWorking() {
	if ctl := svr.currentControl(); ctl != nil {
		<-ctl.Done()
	}

	// There is a situation where the login is successful but due to certain reasons,
	// the control immediately exits. It is necessary to limit the frequency of reconnection in this case.
	// The interval for the first three retries in 1 minute will be very short, and then it will increase exponentially.
	// The maximum interval is 20 seconds.
	wait.BackoffUntil(func() (bool, error) {
		// loopLoginUntilSuccess is another layer of loop that will continuously attempt to
		// login to the server until successful.
		svr.loopLoginUntilSuccess(20*time.Second, false)
		if ctl := svr.currentControl(); ctl != nil {
			<-ctl.Done()
			return false, errors.New("control is closed and try another loop")
		}
		// If the control is nil, it means that the login failed and the service is also closed.
		return false, nil
	}, wait.NewFastBackoffManager(
		wait.FastBackoffOptions{
			Duration:        time.Second,
			Factor:          2,
			Jitter:          0.1,
			MaxDuration:     20 * time.Second,
			FastRetryCount:  3,
			FastRetryDelay:  200 * time.Millisecond,
			FastRetryWindow: time.Minute,
			FastRetryJitter: 0.5,
		},
	), true, svr.ctx.Done())
}

func (svr *Service) loopLoginUntilSuccess(maxInterval time.Duration, firstLoginExit bool) {
	xl := xlog.FromContextSafe(svr.ctx)

	loginFunc := func() (bool, error) {
		xl.Infof("try to connect to server...")
		svr.cfgMu.RLock()
		needBinding := configsNeedXTCPBinding(svr.proxyCfgs, svr.visitorCfgs)
		svr.cfgMu.RUnlock()
		dialer := &controlSessionDialer{
			ctx:                 svr.ctx,
			xtcpBindingRequired: needBinding,
			common:              svr.common,
			auth:                svr.auth,
			clientSpec:          svr.clientSpec,
			vnetController:      svr.vnetController,
			connectorCreator:    svr.connectorCreator,
		}
		sessionCtx, err := dialer.Dial(svr.runID)
		if err != nil {
			xl.Warnf("connect to server error: %v", err)
			svr.cfgMu.RLock()
			changed := configsNeedXTCPBinding(svr.proxyCfgs, svr.visitorCfgs) != needBinding
			// An obsolete negotiation must not terminate the newly published
			// configuration, including XTCP removal during an initial login.
			if firstLoginExit && !changed {
				svr.cancel(cancelErr{Err: err})
			}
			svr.cfgMu.RUnlock()
			return false, err
		}

		// Dial and connection close stay outside cfg/ctl publication locks. A reload
		// between Dial and installation must not put XTCP on an unbound login.
		svr.cfgMu.Lock()
		svr.ctlMu.Lock()
		if svr.ctx.Err() != nil {
			svr.ctlMu.Unlock()
			svr.cfgMu.Unlock()
			sessionCtx.Conn.Close()
			sessionCtx.Connector.Close()
			return false, svr.ctx.Err()
		}
		if configsNeedXTCPBinding(svr.proxyCfgs, svr.visitorCfgs) != needBinding {
			svr.ctlMu.Unlock()
			svr.cfgMu.Unlock()
			sessionCtx.Conn.Close()
			sessionCtx.Connector.Close()
			return false, fmt.Errorf("XTCP binding requirement changed during login")
		}
		// Prefixes are immutable once workers receive their logger. Each actual
		// Control gets a child logger rather than mutating the Service's logger.
		controlLogger := xl.Spawn().AddPrefix(xlog.LogPrefix{Name: "runID", Value: sessionCtx.RunID})
		ctl, err := NewControl(xlog.NewContext(svr.ctx, controlLogger), sessionCtx)
		if err == nil {
			err = ctl.checkConfigAdmission(svr.proxyCfgs, svr.visitorCfgs)
		}
		if err != nil {
			svr.ctlMu.Unlock()
			svr.cfgMu.Unlock()
			if ctl != nil {
				ctl.cancel()
			}
			sessionCtx.Conn.Close()
			sessionCtx.Connector.Close()
			xl.Infof("configuration requires a new authenticated control: %v", err)
			return false, err
		}
		ctl.SetInWorkConnCallback(svr.handleWorkConnCb)
		// Only the local managers and their workers are started here.
		if err = ctl.Run(svr.proxyCfgs, svr.visitorCfgs); err != nil {
			svr.ctlMu.Unlock()
			svr.cfgMu.Unlock()
			ctl.Close()
			return false, err
		}
		old := svr.ctl
		svr.ctl = ctl
		svr.runID = sessionCtx.RunID
		controlLogger.Infof("login to server success, get run id [%s]", svr.runID)
		svr.ctlMu.Unlock()
		svr.cfgMu.Unlock()
		// Close only the captured old instance, never the newly published one.
		if old != nil {
			old.Close()
		}

		return true, nil
	}

	// try to reconnect to server until success
	wait.BackoffUntil(loginFunc, wait.NewFastBackoffManager(
		wait.FastBackoffOptions{
			Duration:    time.Second,
			Factor:      2,
			Jitter:      0.1,
			MaxDuration: maxInterval,
		}), true, svr.ctx.Done())
}

func (svr *Service) UpdateAllConfigurer(proxyCfgs []v1.ProxyConfigurer, visitorCfgs []v1.VisitorConfigurer) error {
	needBinding := configsNeedXTCPBinding(proxyCfgs, visitorCfgs)
	if needBinding && !canRequestXTCPBinding(svr.common, svr.auth, svr.clientSpec) {
		return fmt.Errorf("XTCP requires verified TLS, Token authentication and v2 control")
	}
	// Same ordering as login installation; publish the full config against one
	// actual Control. Network close is outside both publication locks.
	svr.cfgMu.Lock()
	svr.ctlMu.RLock()
	ctl := svr.ctl
	svr.proxyCfgs = proxyCfgs
	svr.visitorCfgs = visitorCfgs
	if ctl == nil || ctl.ctx.Err() != nil {
		svr.ctlMu.RUnlock()
		svr.cfgMu.Unlock()
		return nil
	}
	if needBinding && !ctl.hasXTCPBinding() {
		svr.ctlMu.RUnlock()
		svr.cfgMu.Unlock()
		// Existing keepControllerWorking waits for Done then logs in using the
		// new actual config. Do not start XTCP on the old unbound pm/vm.
		return ctl.Close()
	}
	err := ctl.UpdateAllConfigurer(proxyCfgs, visitorCfgs)
	svr.ctlMu.RUnlock()
	svr.cfgMu.Unlock()
	return err
}

func (svr *Service) UpdateConfigSource(
	common *v1.ClientCommonConfig,
	proxyCfgs []v1.ProxyConfigurer,
	visitorCfgs []v1.VisitorConfigurer,
) error {
	svr.reloadMu.Lock()
	defer svr.reloadMu.Unlock()

	cfgSource := svr.configSource
	if cfgSource == nil {
		return fmt.Errorf("config source is not available")
	}

	if err := cfgSource.ReplaceAll(proxyCfgs, visitorCfgs); err != nil {
		return err
	}

	// Non-atomic update semantics: source has been updated at this point.
	// Even if reload fails below, keep this common config for subsequent reloads.
	svr.cfgMu.Lock()
	svr.reloadCommon = common
	svr.cfgMu.Unlock()

	if err := svr.reloadConfigFromSourcesLocked(); err != nil {
		return err
	}
	return nil
}

func (svr *Service) Close() {
	svr.GracefulClose(time.Duration(0))
}

func (svr *Service) GracefulClose(d time.Duration) {
	svr.gracefulShutdownDuration.Store(int64(d))
	svr.cancel(nil)
}

func (svr *Service) stop() {
	// Coordinate shutdown with reload/update paths that read source pointers.
	svr.reloadMu.Lock()
	if svr.aggregator != nil {
		svr.aggregator = nil
	}
	svr.configSource = nil
	svr.storeSource = nil
	svr.reloadMu.Unlock()

	svr.ctlMu.Lock()
	defer svr.ctlMu.Unlock()
	if svr.ctl != nil {
		d := time.Duration(svr.gracefulShutdownDuration.Load())
		svr.ctl.GracefulClose(d)
		svr.ctl = nil
	}
	if svr.webServer != nil {
		svr.webServer.Close()
		svr.webServer = nil
	}
	if svr.vnetController != nil {
		_ = svr.vnetController.Stop()
		svr.vnetController = nil
	}
}

func (svr *Service) getProxyStatus(name string) (*proxy.WorkingStatus, bool) {
	svr.ctlMu.RLock()
	ctl := svr.ctl
	svr.ctlMu.RUnlock()

	if ctl == nil {
		return nil, false
	}
	return ctl.pm.GetProxyStatus(name)
}

func (svr *Service) getVisitorCfg(name string) (v1.VisitorConfigurer, bool) {
	svr.ctlMu.RLock()
	ctl := svr.ctl
	svr.ctlMu.RUnlock()

	if ctl == nil {
		return nil, false
	}
	return ctl.vm.GetVisitorCfg(name)
}

func (svr *Service) StatusExporter() StatusExporter {
	return &statusExporterImpl{
		getProxyStatusFunc: svr.getProxyStatus,
	}
}

type StatusExporter interface {
	GetProxyStatus(name string) (*proxy.WorkingStatus, bool)
}

type statusExporterImpl struct {
	getProxyStatusFunc func(name string) (*proxy.WorkingStatus, bool)
}

func (s *statusExporterImpl) GetProxyStatus(name string) (*proxy.WorkingStatus, bool) {
	return s.getProxyStatusFunc(name)
}

func (svr *Service) reloadConfigFromSources() error {
	svr.reloadMu.Lock()
	defer svr.reloadMu.Unlock()
	return svr.reloadConfigFromSourcesLocked()
}

func (svr *Service) reloadConfigFromSourcesLocked() error {
	aggregator := svr.aggregator
	if aggregator == nil {
		return errors.New("config aggregator is not initialized")
	}

	svr.cfgMu.RLock()
	reloadCommon := svr.reloadCommon
	svr.cfgMu.RUnlock()

	proxies, visitors, err := aggregator.Load()
	if err != nil {
		return fmt.Errorf("reload config from sources failed: %w", err)
	}

	proxies, visitors = config.FilterClientConfigurers(reloadCommon, proxies, visitors)
	proxies = config.CompleteProxyConfigurers(proxies)
	visitors = config.CompleteVisitorConfigurers(visitors)
	requirements := validation.GetClientConfigRequirements(reloadCommon, proxies, visitors)
	if svr.vnetController == nil && requirements.VirtualNet {
		return errors.New(
			"VirtualNet-dependent configuration requires a VirtualNet runtime enabled at startup; " +
				"restart frpc after configuring featureGates.VirtualNet and virtualNet.address",
		)
	}

	// Atomically replace the entire configuration
	if err := svr.UpdateAllConfigurer(proxies, visitors); err != nil {
		return err
	}
	return nil
}
