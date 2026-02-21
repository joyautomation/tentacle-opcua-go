package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/monitor"
	"github.com/gopcua/opcua/ua"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

// OpcUaConnection holds a connection to a single OPC UA device.
type OpcUaConnection struct {
	DeviceID            string
	EndpointURL         string
	SecurityPolicy      string
	SecurityMode        string
	Auth                OpcUaAuth
	Client              *opcua.Client
	NodeMonitor         *monitor.NodeMonitor
	MonitorSub          *monitor.Subscription // active subscription on the NodeMonitor
	Variables           map[string]*CachedVariable // nodeId → cached variable
	ConnectionState     string                     // "disconnected", "connecting", "connected"
	ConsecutiveFailures int
	LastConnectAttempt  time.Time
	cancel              context.CancelFunc
}

// DeviceSubscription tracks a subscriber's interest in specific nodes.
type DeviceSubscription struct {
	SubscriberID string
	NodeIDs      map[string]bool
	ScanRate     int
}

// Scanner manages OPC UA connections and NATS handlers.
type Scanner struct {
	nc              *nats.Conn
	connections     map[string]*OpcUaConnection                // deviceID → connection
	subscribers     map[string]map[string]*DeviceSubscription  // deviceID → subscriberID → sub
	certFile        string
	keyFile         string
	pkiDir          string
	autoAcceptCerts bool
	mu              sync.RWMutex
	subs            []*nats.Subscription
}

// NewScanner creates a new scanner instance.
func NewScanner(nc *nats.Conn, certFile, keyFile, pkiDir string, autoAcceptCerts bool) *Scanner {
	return &Scanner{
		nc:              nc,
		connections:     make(map[string]*OpcUaConnection),
		subscribers:     make(map[string]map[string]*DeviceSubscription),
		certFile:        certFile,
		keyFile:         keyFile,
		pkiDir:          pkiDir,
		autoAcceptCerts: autoAcceptCerts,
	}
}

// Start begins listening for NATS requests.
func (s *Scanner) Start() {
	logInfo("opcua", "Starting OPC UA scanner (stateless, subscriber-driven)...")
	logInfo("opcua", "Zero connections — devices will connect on subscribe/browse")

	s.startRequestHandlers()

	logInfo("opcua", "Scanner started, waiting for subscribe/browse requests")
}

// Stop shuts down all connections and NATS subscriptions.
func (s *Scanner) Stop() {
	logInfo("opcua", "Stopping OPC UA scanner...")

	for _, sub := range s.subs {
		_ = sub.Unsubscribe()
	}

	s.mu.Lock()
	for deviceID, conn := range s.connections {
		s.disconnectDevice(conn)
		logInfo("opcua:client", "Disconnected %s", deviceID)
	}
	s.connections = make(map[string]*OpcUaConnection)
	s.subscribers = make(map[string]map[string]*DeviceSubscription)
	s.mu.Unlock()

	logInfo("opcua", "Scanner stopped")
}

// ═══════════════════════════════════════════════════════════════════════════
// Connection Management
// ═══════════════════════════════════════════════════════════════════════════

func (s *Scanner) connectDevice(
	deviceID, endpointURL string,
	auth *OpcUaAuth,
	securityPolicy, securityMode string,
) (*OpcUaConnection, error) {
	s.mu.Lock()
	conn, exists := s.connections[deviceID]
	if exists && conn.Client != nil && conn.ConnectionState == "connected" {
		s.mu.Unlock()
		return conn, nil
	}

	if !exists {
		authVal := OpcUaAuth{Type: "anonymous"}
		if auth != nil {
			authVal = *auth
		}
		conn = &OpcUaConnection{
			DeviceID:       deviceID,
			EndpointURL:    endpointURL,
			SecurityPolicy: securityPolicy,
			SecurityMode:   securityMode,
			Auth:           authVal,
			Variables:      make(map[string]*CachedVariable),
		}
		s.connections[deviceID] = conn
	}
	conn.ConnectionState = "connecting"
	conn.LastConnectAttempt = time.Now()
	s.mu.Unlock()

	logInfo("opcua:client", "[%s] Connecting to %s...", deviceID, endpointURL)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Discover endpoints
	endpoints, err := opcua.GetEndpoints(ctx, endpointURL)
	if err != nil {
		s.mu.Lock()
		conn.ConnectionState = "disconnected"
		conn.ConsecutiveFailures++
		s.mu.Unlock()
		return nil, fmt.Errorf("get endpoints: %w", err)
	}

	// Select endpoint based on security policy
	ep := selectEndpoint(endpoints, securityPolicy, securityMode)
	if ep == nil {
		s.mu.Lock()
		conn.ConnectionState = "disconnected"
		conn.ConsecutiveFailures++
		s.mu.Unlock()
		return nil, fmt.Errorf("no matching endpoint for policy=%s mode=%s", securityPolicy, securityMode)
	}

	logInfo("opcua:client", "[%s] Selected endpoint: %s / %s (url: %s)",
		deviceID, ep.SecurityPolicyURI, securityModeStr(ep.SecurityMode), ep.EndpointURL)

	// Auth options
	authType := "anonymous"
	if auth != nil {
		authType = auth.Type
	}

	var userTokenType ua.UserTokenType
	switch authType {
	case "username":
		userTokenType = ua.UserTokenTypeUserName
	case "certificate":
		userTokenType = ua.UserTokenTypeCertificate
	default:
		userTokenType = ua.UserTokenTypeAnonymous
	}

	// Build client options
	opts := []opcua.Option{
		opcua.SecurityFromEndpoint(ep, userTokenType),
		opcua.ApplicationURI("urn:tentacle-opcua"),
		opcua.AutoReconnect(true),
		opcua.ReconnectInterval(10 * time.Second),
	}

	if authType == "username" {
		opts = append(opts, opcua.AuthUsername(auth.Username, auth.Password))
	}

	// Add certificate if security is not None
	if ep.SecurityPolicyURI != ua.SecurityPolicyURINone {
		opts = append(opts,
			opcua.CertificateFile(s.certFile),
			opcua.PrivateKeyFile(s.keyFile),
		)
	}

	// Use the original endpointUrl if the server's advertised URL differs
	// (server may advertise an internal hostname we can't reach)
	connectURL := ep.EndpointURL
	if ep.EndpointURL != endpointURL {
		logInfo("opcua:client", "[%s] Server advertised %s, using original %s instead",
			deviceID, ep.EndpointURL, endpointURL)
		connectURL = endpointURL
	}

	client, err := opcua.NewClient(connectURL, opts...)
	if err != nil {
		s.mu.Lock()
		conn.ConnectionState = "disconnected"
		conn.ConsecutiveFailures++
		s.mu.Unlock()
		return nil, fmt.Errorf("create client: %w", err)
	}

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer connectCancel()

	if err := client.Connect(connectCtx); err != nil {
		s.mu.Lock()
		conn.ConnectionState = "disconnected"
		conn.ConsecutiveFailures++
		s.mu.Unlock()
		return nil, fmt.Errorf("connect: %w", err)
	}

	s.mu.Lock()
	conn.Client = client
	conn.ConnectionState = "connected"
	conn.ConsecutiveFailures = 0
	s.mu.Unlock()

	logInfo("opcua:client", "[%s] Connected", deviceID)
	return conn, nil
}

func (s *Scanner) disconnectDevice(conn *OpcUaConnection) {
	if conn.cancel != nil {
		conn.cancel()
	}
	if conn.MonitorSub != nil {
		_ = conn.MonitorSub.Unsubscribe(context.Background())
		conn.MonitorSub = nil
	}
	conn.NodeMonitor = nil
	if conn.Client != nil {
		if err := conn.Client.Close(context.Background()); err != nil {
			logDebug("opcua:client", "Close error for %s: %v", conn.DeviceID, err)
		}
		conn.Client = nil
	}
	conn.ConnectionState = "disconnected"
}

func (s *Scanner) removeConnection(deviceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	conn, ok := s.connections[deviceID]
	if !ok {
		return
	}
	s.disconnectDevice(conn)
	delete(s.connections, deviceID)
	logInfo("opcua:client", "Removed connection for %s", deviceID)
}

func selectEndpoint(endpoints []*ua.EndpointDescription, policy, mode string) *ua.EndpointDescription {
	policyLower := strings.ToLower(policy)

	// Map policy name to URI
	policyURIs := map[string]string{
		"none":           ua.SecurityPolicyURINone,
		"basic128rsa15":  ua.SecurityPolicyURIBasic128Rsa15,
		"basic256":       ua.SecurityPolicyURIBasic256,
		"basic256sha256": ua.SecurityPolicyURIBasic256Sha256,
		"":               "", // any
	}

	targetURI := policyURIs[policyLower]

	// Map mode name to enum
	modeLower := strings.ToLower(mode)
	var targetMode ua.MessageSecurityMode
	switch modeLower {
	case "sign":
		targetMode = ua.MessageSecurityModeSign
	case "signandencrypt":
		targetMode = ua.MessageSecurityModeSignAndEncrypt
	case "none", "":
		targetMode = ua.MessageSecurityModeNone
	}

	// If no policy specified, prefer the most secure endpoint
	if targetURI == "" {
		var best *ua.EndpointDescription
		for _, ep := range endpoints {
			if best == nil || ep.SecurityMode > best.SecurityMode {
				best = ep
			}
		}
		return best
	}

	// Find matching endpoint
	for _, ep := range endpoints {
		if ep.SecurityPolicyURI == targetURI {
			if targetMode == 0 || ep.SecurityMode == targetMode {
				return ep
			}
		}
	}

	// Fallback: any endpoint with the requested policy
	for _, ep := range endpoints {
		if ep.SecurityPolicyURI == targetURI {
			return ep
		}
	}

	return nil
}

func securityModeStr(mode ua.MessageSecurityMode) string {
	switch mode {
	case ua.MessageSecurityModeNone:
		return "None"
	case ua.MessageSecurityModeSign:
		return "Sign"
	case ua.MessageSecurityModeSignAndEncrypt:
		return "SignAndEncrypt"
	default:
		return fmt.Sprintf("Unknown(%d)", mode)
	}
}

func getBackoffDelay(failures int) time.Duration {
	base := 2 * time.Second
	maxDelay := 60 * time.Second
	delay := time.Duration(float64(base) * math.Pow(2, float64(failures)))
	if delay > maxDelay {
		delay = maxDelay
	}
	return delay
}

// ═══════════════════════════════════════════════════════════════════════════
// Subscriber Management
// ═══════════════════════════════════════════════════════════════════════════

func (s *Scanner) getDeviceSubscribedNodeIDs(deviceID string) map[string]bool {
	nodeIDs := make(map[string]bool)
	subs, ok := s.subscribers[deviceID]
	if !ok {
		return nodeIDs
	}
	for _, sub := range subs {
		for nodeID := range sub.NodeIDs {
			nodeIDs[nodeID] = true
		}
	}
	return nodeIDs
}

func (s *Scanner) addSubscriber(deviceID, subscriberID string, nodeIDs []string, scanRate int) {
	if _, ok := s.subscribers[deviceID]; !ok {
		s.subscribers[deviceID] = make(map[string]*DeviceSubscription)
	}
	subs := s.subscribers[deviceID]

	existing, ok := subs[subscriberID]
	if ok {
		for _, nodeID := range nodeIDs {
			existing.NodeIDs[nodeID] = true
		}
		existing.ScanRate = scanRate
	} else {
		ids := make(map[string]bool)
		for _, nodeID := range nodeIDs {
			ids[nodeID] = true
		}
		subs[subscriberID] = &DeviceSubscription{
			SubscriberID: subscriberID,
			NodeIDs:      ids,
			ScanRate:     scanRate,
		}
	}

	logInfo("opcua:client", "Subscribed %d nodeIds for %s on device %s, total subscribers: %d",
		len(nodeIDs), subscriberID, deviceID, len(subs))
}

// removeSubscriber removes nodeIDs for a subscriber. Returns true if zero subscribers remain.
func (s *Scanner) removeSubscriber(deviceID, subscriberID string, nodeIDs []string) bool {
	subs, ok := s.subscribers[deviceID]
	if !ok {
		return true
	}

	existing, ok := subs[subscriberID]
	if ok {
		for _, nodeID := range nodeIDs {
			delete(existing.NodeIDs, nodeID)
		}
		if len(existing.NodeIDs) == 0 {
			delete(subs, subscriberID)
		}
	}

	if len(subs) == 0 {
		delete(s.subscribers, deviceID)
		return true
	}
	return false
}

// ═══════════════════════════════════════════════════════════════════════════
// Publishing
// ═══════════════════════════════════════════════════════════════════════════

func (s *Scanner) publishValue(conn *OpcUaConnection, nodeID string, value interface{}, datatype, quality string) {
	if value == nil {
		return
	}

	now := time.Now().UnixMilli()

	// Update cached variable
	if cached, ok := conn.Variables[nodeID]; ok {
		cached.Value = value
		cached.Quality = quality
		cached.LastUpdated = now
	}

	description := nodeID
	if cached, ok := conn.Variables[nodeID]; ok && cached.DisplayName != "" {
		description = cached.DisplayName
	}

	msg := PlcDataMessage{
		ModuleID:    moduleID,
		DeviceID:    conn.DeviceID,
		VariableID:  nodeID,
		Value:       value,
		Timestamp:   now,
		Datatype:    datatype,
		Description: description,
	}

	data, err := json.Marshal(msg)
	if err != nil {
		logError("opcua:client", "Failed to marshal data message: %v", err)
		return
	}

	sanitizedNodeID := sanitizeNodeIDForSubject(nodeID)
	subject := fmt.Sprintf("%s.data.%s.%s", moduleID, conn.DeviceID, sanitizedNodeID)
	_ = s.nc.Publish(subject, data)
}

func (s *Scanner) publishBrowseProgress(browseID, deviceID, phase string, totalTags, completedTags, errorCount int, message string) {
	msg := BrowseProgressMessage{
		BrowseID:      browseID,
		ModuleID:      moduleID,
		DeviceID:      deviceID,
		Phase:         phase,
		TotalTags:     totalTags,
		CompletedTags: completedTags,
		ErrorCount:    errorCount,
		Message:       message,
		Timestamp:     time.Now().UnixMilli(),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return
	}

	subject := fmt.Sprintf("%s.browse.progress.%s", moduleID, browseID)
	_ = s.nc.Publish(subject, data)
}

// ═══════════════════════════════════════════════════════════════════════════
// Browse Handler
// ═══════════════════════════════════════════════════════════════════════════

func (s *Scanner) browseDevice(
	deviceID, endpointURL string,
	auth *OpcUaAuth,
	securityPolicy, securityMode string,
	startNodeID, browseID string,
	maxDepth int,
) []VariableInfo {
	s.mu.RLock()
	conn, exists := s.connections[deviceID]
	hasSession := exists && conn.Client != nil && conn.ConnectionState == "connected"
	s.mu.RUnlock()

	tempConnection := false

	if !hasSession {
		if browseID != "" {
			s.publishBrowseProgress(browseID, deviceID, "discovering", 0, 0, 0, "Connecting to OPC UA server...")
		}

		var err error
		conn, err = s.connectDevice(deviceID, endpointURL, auth, securityPolicy, securityMode)
		if err != nil {
			logError("opcua:browse", "Failed to connect to %s for browse: %v", deviceID, err)
			if browseID != "" {
				s.publishBrowseProgress(browseID, deviceID, "failed", 0, 0, 1,
					fmt.Sprintf("Connection failed: %v", err))
			}
			return nil
		}

		s.mu.RLock()
		_, hasSubs := s.subscribers[deviceID]
		s.mu.RUnlock()
		tempConnection = !hasSubs
	}

	if conn == nil || conn.Client == nil {
		logError("opcua:browse", "No client for %s", deviceID)
		return nil
	}

	if browseID != "" {
		s.publishBrowseProgress(browseID, deviceID, "discovering", 0, 0, 0, "Browsing address space...")
	}

	if startNodeID == "" {
		startNodeID = "i=85" // Objects folder
	}
	if maxDepth <= 0 {
		maxDepth = 10
	}

	var progressFn BrowseProgressFunc
	if browseID != "" {
		progressFn = func(total int, nodeID string, message string) {
			s.publishBrowseProgress(browseID, deviceID, "discovering", total, total, 0, message)
		}
	}

	ctx := context.Background()
	browseResults, err := browseAddressSpace(ctx, conn.Client, startNodeID, maxDepth, progressFn)
	if err != nil {
		logError("opcua:browse", "Browse failed for %s: %v", deviceID, err)
		if browseID != "" {
			s.publishBrowseProgress(browseID, deviceID, "failed", 0, 0, 1,
				fmt.Sprintf("Browse failed: %v", err))
		}
		return nil
	}

	// Cache discovered variables
	s.mu.Lock()
	for _, v := range browseResults {
		if _, exists := conn.Variables[v.NodeID]; !exists {
			conn.Variables[v.NodeID] = &CachedVariable{
				NodeID:        v.NodeID,
				DisplayName:   v.DisplayName,
				Datatype:      v.Datatype,
				OpcuaDatatype: v.OpcuaDatatype,
				Value:         nil,
				Quality:       "unknown",
				LastUpdated:   0,
			}
		}
	}
	s.mu.Unlock()

	// Disconnect temp connection but keep cached variables
	if tempConnection && conn.Client != nil {
		s.mu.Lock()
		if conn.cancel != nil {
			conn.cancel()
		}
		if conn.MonitorSub != nil {
			_ = conn.MonitorSub.Unsubscribe(context.Background())
			conn.MonitorSub = nil
		}
		conn.NodeMonitor = nil
		if conn.Client != nil {
			_ = conn.Client.Close(context.Background())
			conn.Client = nil
		}
		conn.ConnectionState = "disconnected"
		s.mu.Unlock()
	}

	if browseID != "" {
		s.publishBrowseProgress(browseID, deviceID, "completed", len(browseResults), len(browseResults), 0,
			fmt.Sprintf("Browse complete: %d variables", len(browseResults)))
	}

	// Build response
	results := make([]VariableInfo, len(browseResults))
	for i, v := range browseResults {
		results[i] = VariableInfo{
			ModuleID:      moduleID,
			DeviceID:      deviceID,
			VariableID:    v.NodeID,
			DisplayName:   v.DisplayName,
			Value:         nil,
			Datatype:      v.Datatype,
			OpcuaDatatype: v.OpcuaDatatype,
			Quality:       "unknown",
			Origin:        "opcua",
			LastUpdated:   0,
		}
	}

	return results
}

// ═══════════════════════════════════════════════════════════════════════════
// NATS Request Handlers
// ═══════════════════════════════════════════════════════════════════════════

func (s *Scanner) startRequestHandlers() {
	// Variables handler
	sub, err := s.nc.Subscribe(moduleID+".variables", s.handleVariables)
	if err != nil {
		logError("opcua:nats", "Failed to subscribe to variables: %v", err)
	} else {
		s.subs = append(s.subs, sub)
		logInfo("opcua:nats", "Listening for variable requests on %s.variables", moduleID)
	}

	// Browse handler
	sub, err = s.nc.Subscribe(moduleID+".browse", s.handleBrowse)
	if err != nil {
		logError("opcua:nats", "Failed to subscribe to browse: %v", err)
	} else {
		s.subs = append(s.subs, sub)
		logInfo("opcua:nats", "Listening for browse requests on %s.browse", moduleID)
	}

	// Subscribe handler
	sub, err = s.nc.Subscribe(moduleID+".subscribe", s.handleSubscribe)
	if err != nil {
		logError("opcua:nats", "Failed to subscribe to subscribe: %v", err)
	} else {
		s.subs = append(s.subs, sub)
		logInfo("opcua:nats", "Listening for subscribe requests on %s.subscribe", moduleID)
	}

	// Unsubscribe handler
	sub, err = s.nc.Subscribe(moduleID+".unsubscribe", s.handleUnsubscribe)
	if err != nil {
		logError("opcua:nats", "Failed to subscribe to unsubscribe: %v", err)
	} else {
		s.subs = append(s.subs, sub)
		logInfo("opcua:nats", "Listening for unsubscribe requests on %s.unsubscribe", moduleID)
	}

	// Write command handler
	sub, err = s.nc.Subscribe(moduleID+".command.>", s.handleWriteCommand)
	if err != nil {
		logError("opcua:nats", "Failed to subscribe to commands: %v", err)
	} else {
		s.subs = append(s.subs, sub)
		logInfo("opcua:nats", "Listening for write commands on %s.command.>", moduleID)
	}
}

func (s *Scanner) handleVariables(msg *nats.Msg) {
	s.mu.RLock()
	var allVars []VariableInfo
	for deviceID, conn := range s.connections {
		for _, cached := range conn.Variables {
			allVars = append(allVars, VariableInfo{
				ModuleID:      moduleID,
				DeviceID:      deviceID,
				VariableID:    cached.NodeID,
				DisplayName:   cached.DisplayName,
				Value:         cached.Value,
				Datatype:      cached.Datatype,
				OpcuaDatatype: cached.OpcuaDatatype,
				Quality:       cached.Quality,
				Origin:        "opcua",
				LastUpdated:   cached.LastUpdated,
			})
		}
	}
	s.mu.RUnlock()

	logInfo("opcua:nats", "Variables request: returning %d variables", len(allVars))

	data, err := json.Marshal(allVars)
	if err != nil {
		_ = msg.Respond([]byte("[]"))
		return
	}
	_ = msg.Respond(data)
}

func (s *Scanner) handleBrowse(msg *nats.Msg) {
	var req BrowseRequest
	if len(msg.Data) > 0 {
		if err := json.Unmarshal(msg.Data, &req); err != nil {
			logError("opcua:nats", "Invalid browse request: %v", err)
			_ = msg.Respond([]byte("[]"))
			return
		}
	}

	if req.DeviceID == "" || req.EndpointURL == "" {
		resp, _ := json.Marshal(map[string]string{
			"error": "Browse requires deviceId and endpointUrl",
		})
		_ = msg.Respond(resp)
		return
	}

	browseID := req.BrowseID
	if browseID == "" && req.Async {
		browseID = uuid.New().String()
	}

	if req.Async && browseID != "" {
		logInfo("opcua:nats", "Browse request (async): %s at %s, ID %s", req.DeviceID, req.EndpointURL, browseID)

		// Reply immediately with browseId
		resp, _ := json.Marshal(map[string]string{"browseId": browseID})
		_ = msg.Respond(resp)

		// Run browse in background
		go func() {
			results := s.browseDevice(
				req.DeviceID, req.EndpointURL,
				req.Auth, req.SecurityPolicy, req.SecurityMode,
				req.StartNodeID, browseID, req.MaxDepth,
			)
			s.publishBrowseProgress(browseID, "_all", "completed", len(results), len(results), 0,
				fmt.Sprintf("Browse complete: %d total variables", len(results)))
		}()
		return
	}

	// Synchronous browse
	results := s.browseDevice(
		req.DeviceID, req.EndpointURL,
		req.Auth, req.SecurityPolicy, req.SecurityMode,
		req.StartNodeID, browseID, req.MaxDepth,
	)

	logInfo("opcua:nats", "Browse request: returning %d variables", len(results))
	data, err := json.Marshal(results)
	if err != nil {
		_ = msg.Respond([]byte("[]"))
		return
	}
	_ = msg.Respond(data)
}

func (s *Scanner) handleSubscribe(msg *nats.Msg) {
	var req SubscribeRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		logError("opcua:nats", "Invalid subscribe request: %v", err)
		resp, _ := json.Marshal(map[string]interface{}{"success": false, "error": err.Error()})
		_ = msg.Respond(resp)
		return
	}

	if req.DeviceID == "" || req.EndpointURL == "" || len(req.NodeIDs) == 0 || req.SubscriberID == "" {
		resp, _ := json.Marshal(map[string]interface{}{
			"success": false,
			"error":   "Subscribe requires deviceId, endpointUrl, nodeIds, and subscriberId",
		})
		_ = msg.Respond(resp)
		return
	}

	scanRate := req.ScanRate
	if scanRate <= 0 {
		scanRate = 1000
	}

	// Track subscriber
	s.mu.Lock()
	s.addSubscriber(req.DeviceID, req.SubscriberID, req.NodeIDs, scanRate)
	s.mu.Unlock()

	// Connect if needed
	conn, err := s.connectDevice(req.DeviceID, req.EndpointURL, req.Auth, req.SecurityPolicy, req.SecurityMode)
	if err != nil {
		resp, _ := json.Marshal(map[string]interface{}{
			"success": false,
			"error":   fmt.Sprintf("Connection failed: %v", err),
		})
		_ = msg.Respond(resp)
		return
	}

	// Set up monitoring via gopcua's monitor package
	s.mu.Lock()
	if conn.NodeMonitor == nil && conn.Client != nil {
		ctx, cancel := context.WithCancel(context.Background())
		conn.cancel = cancel

		nm, err := monitor.NewNodeMonitor(conn.Client)
		if err != nil {
			s.mu.Unlock()
			logError("opcua:client", "Failed to create node monitor: %v", err)
			resp, _ := json.Marshal(map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("Monitor creation failed: %v", err),
			})
			_ = msg.Respond(resp)
			return
		}
		conn.NodeMonitor = nm

		// Start the subscription channel reader
		ch := make(chan *monitor.DataChangeMessage, 256)
		monSub, err := nm.ChanSubscribe(
			ctx,
			&opcua.SubscriptionParameters{
				Interval: time.Duration(scanRate) * time.Millisecond,
			},
			ch,
			req.NodeIDs...,
		)
		if err != nil {
			s.mu.Unlock()
			logError("opcua:client", "Failed to create subscription: %v", err)
			resp, _ := json.Marshal(map[string]interface{}{
				"success": false,
				"error":   fmt.Sprintf("Subscription failed: %v", err),
			})
			_ = msg.Respond(resp)
			return
		}
		conn.MonitorSub = monSub

		// Ensure variable entries exist for all subscribed nodes
		for _, nodeID := range req.NodeIDs {
			if _, exists := conn.Variables[nodeID]; !exists {
				conn.Variables[nodeID] = &CachedVariable{
					NodeID:        nodeID,
					DisplayName:   nodeID,
					Datatype:      "string",
					OpcuaDatatype: "String",
					Value:         nil,
					Quality:       "unknown",
					LastUpdated:   0,
				}
			}
		}
		s.mu.Unlock()

		// Read data changes in a goroutine
		go func() {
			for dcm := range ch {
				if dcm.Error != nil {
					logDebug("opcua:client", "Data change error: %v", dcm.Error)
					continue
				}

				nodeID := dcm.NodeID.String()
				value := extractValue(dcm.Value)

				quality := "good"
				if dcm.Status != ua.StatusOK {
					quality = "bad"
				}

				s.mu.RLock()
				cached, ok := conn.Variables[nodeID]
				datatype := "string"
				if ok {
					datatype = cached.Datatype
					// Infer datatype from first value
					if datatype == "string" {
						switch value.(type) {
						case int64, uint64, float64:
							datatype = "number"
							cached.Datatype = "number"
						case bool:
							datatype = "boolean"
							cached.Datatype = "boolean"
						}
					}
				}
				s.mu.RUnlock()

				s.publishValue(conn, nodeID, value, datatype, quality)
			}
		}()
	} else if conn.NodeMonitor != nil {
		// Already have a monitor — add new nodes to existing subscription
		for _, nodeID := range req.NodeIDs {
			if _, exists := conn.Variables[nodeID]; !exists {
				conn.Variables[nodeID] = &CachedVariable{
					NodeID:        nodeID,
					DisplayName:   nodeID,
					Datatype:      "string",
					OpcuaDatatype: "String",
					Value:         nil,
					Quality:       "unknown",
					LastUpdated:   0,
				}
			}
		}
		s.mu.Unlock()
	} else {
		s.mu.Unlock()
	}

	logInfo("opcua:client", "Subscribe: %d nodeIds monitored on %s", len(req.NodeIDs), req.DeviceID)
	resp, _ := json.Marshal(map[string]interface{}{"success": true, "count": len(req.NodeIDs)})
	_ = msg.Respond(resp)
}

func (s *Scanner) handleUnsubscribe(msg *nats.Msg) {
	var req UnsubscribeRequest
	if err := json.Unmarshal(msg.Data, &req); err != nil {
		logError("opcua:nats", "Invalid unsubscribe request: %v", err)
		resp, _ := json.Marshal(map[string]interface{}{"success": false, "error": err.Error()})
		_ = msg.Respond(resp)
		return
	}

	s.mu.Lock()
	zeroSubscribers := s.removeSubscriber(req.DeviceID, req.SubscriberID, req.NodeIDs)
	s.mu.Unlock()

	if zeroSubscribers {
		logInfo("opcua:client", "No subscribers remaining for %s, closing connection", req.DeviceID)
		s.removeConnection(req.DeviceID)
	}

	resp, _ := json.Marshal(map[string]interface{}{"success": true, "count": len(req.NodeIDs)})
	_ = msg.Respond(resp)
}

func (s *Scanner) handleWriteCommand(msg *nats.Msg) {
	commandPrefix := moduleID + ".command."
	if !strings.HasPrefix(msg.Subject, commandPrefix) {
		return
	}

	variableID := msg.Subject[len(commandPrefix):]
	if variableID == "" {
		logWarn("opcua:client", "Write command with empty variableId: %s", msg.Subject)
		return
	}

	valueStr := string(msg.Data)
	logInfo("opcua:client", "Write command received: %s = %s", variableID, valueStr)

	// Find connection with this variable
	s.mu.RLock()
	var conn *OpcUaConnection
	for _, c := range s.connections {
		if _, ok := c.Variables[variableID]; ok {
			conn = c
			break
		}
	}
	s.mu.RUnlock()

	if conn == nil {
		logWarn("opcua:client", "Write failed: variable %q not found in any connection", variableID)
		return
	}

	if conn.Client == nil || conn.ConnectionState != "connected" {
		logWarn("opcua:client", "Write failed: device %s not connected", conn.DeviceID)
		return
	}

	s.mu.RLock()
	cached := conn.Variables[variableID]
	var datatype string
	if cached != nil {
		datatype = cached.Datatype
	}
	s.mu.RUnlock()

	// Parse value based on datatype
	var writeValue interface{} = valueStr
	switch datatype {
	case "number":
		if v, err := strconv.ParseFloat(valueStr, 64); err == nil {
			writeValue = v
		}
	case "boolean":
		lower := strings.ToLower(valueStr)
		writeValue = lower == "true" || lower == "1" || lower == "on" || lower == "yes"
	}

	// Write to OPC UA
	parsedID, err := ua.ParseNodeID(variableID)
	if err != nil {
		logError("opcua:client", "Invalid NodeID for write: %s: %v", variableID, err)
		return
	}

	variant, err := ua.NewVariant(writeValue)
	if err != nil {
		logError("opcua:client", "Failed to create variant for write: %v", err)
		return
	}

	writeReq := &ua.WriteRequest{
		NodesToWrite: []*ua.WriteValue{
			{
				NodeID:      parsedID,
				AttributeID: ua.AttributeIDValue,
				Value: &ua.DataValue{
					EncodingMask: ua.DataValueValue,
					Value:        variant,
				},
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := conn.Client.Write(ctx, writeReq)
	if err != nil {
		logError("opcua:client", "Write error for %s: %v", variableID, err)
		return
	}

	if len(resp.Results) > 0 && resp.Results[0] != ua.StatusOK {
		logError("opcua:client", "Write failed for %s: status=%s", variableID, resp.Results[0])
	} else {
		logInfo("opcua:client", "Write successful: %s = %v", variableID, writeValue)
	}
}
