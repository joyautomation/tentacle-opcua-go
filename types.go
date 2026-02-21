package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/gopcua/opcua/ua"
)

// ═══════════════════════════════════════════════════════════════════════════
// Authentication
// ═══════════════════════════════════════════════════════════════════════════

// OpcUaAuth holds authentication configuration for OPC UA connections.
type OpcUaAuth struct {
	Type     string `json:"type"`               // "anonymous", "username", "certificate"
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	CertPath string `json:"certPath,omitempty"`
	KeyPath  string `json:"keyPath,omitempty"`
}

// ═══════════════════════════════════════════════════════════════════════════
// NATS Request/Response payloads
// ═══════════════════════════════════════════════════════════════════════════

// BrowseRequest is the JSON payload for opcua.browse requests.
type BrowseRequest struct {
	DeviceID       string     `json:"deviceId"`
	EndpointURL    string     `json:"endpointUrl"`
	SecurityPolicy string     `json:"securityPolicy,omitempty"`
	SecurityMode   string     `json:"securityMode,omitempty"`
	Auth           *OpcUaAuth `json:"auth,omitempty"`
	StartNodeID    string     `json:"startNodeId,omitempty"`
	BrowseID       string     `json:"browseId,omitempty"`
	Async          bool       `json:"async,omitempty"`
	MaxDepth       int        `json:"maxDepth,omitempty"`
}

// SubscribeRequest is the JSON payload for opcua.subscribe requests.
type SubscribeRequest struct {
	DeviceID       string     `json:"deviceId"`
	EndpointURL    string     `json:"endpointUrl"`
	SecurityPolicy string     `json:"securityPolicy,omitempty"`
	SecurityMode   string     `json:"securityMode,omitempty"`
	Auth           *OpcUaAuth `json:"auth,omitempty"`
	NodeIDs        []string   `json:"nodeIds"`
	ScanRate       int        `json:"scanRate,omitempty"`
	SubscriberID   string     `json:"subscriberId"`
}

// UnsubscribeRequest is the JSON payload for opcua.unsubscribe requests.
type UnsubscribeRequest struct {
	DeviceID     string   `json:"deviceId"`
	NodeIDs      []string `json:"nodeIds"`
	SubscriberID string   `json:"subscriberId"`
}

// ═══════════════════════════════════════════════════════════════════════════
// Published message types
// ═══════════════════════════════════════════════════════════════════════════

// PlcDataMessage is published on opcua.data.{deviceId}.{sanitizedNodeId}
// when a monitored variable changes value.
type PlcDataMessage struct {
	ModuleID    string      `json:"moduleId"`
	DeviceID    string      `json:"deviceId"`
	VariableID  string      `json:"variableId"`
	Value       interface{} `json:"value"`
	Timestamp   int64       `json:"timestamp"`
	Datatype    string      `json:"datatype"`
	Description string      `json:"description,omitempty"`
}

// ServiceHeartbeat is published every 10s to the service_heartbeats KV bucket.
type ServiceHeartbeat struct {
	ServiceType string                 `json:"serviceType"`
	ModuleID    string                 `json:"moduleId"`
	LastSeen    int64                  `json:"lastSeen"`
	StartedAt   int64                  `json:"startedAt"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// BrowseProgressMessage is published during async browse operations
// to opcua.browse.progress.{browseId}.
type BrowseProgressMessage struct {
	BrowseID      string `json:"browseId"`
	ModuleID      string `json:"moduleId"`
	DeviceID      string `json:"deviceId"`
	Phase         string `json:"phase"` // "discovering", "expanding", "reading", "caching", "completed", "failed"
	TotalTags     int    `json:"totalTags"`
	CompletedTags int    `json:"completedTags"`
	ErrorCount    int    `json:"errorCount"`
	Message       string `json:"message,omitempty"`
	Timestamp     int64  `json:"timestamp"`
}

// ServiceLogEntry is published to service.logs.opcua.opcua for log streaming.
type ServiceLogEntry struct {
	Timestamp   int64  `json:"timestamp"`
	Level       string `json:"level"`
	Message     string `json:"message"`
	ServiceType string `json:"serviceType"`
	ModuleID    string `json:"moduleId"`
	Logger      string `json:"logger,omitempty"`
}

// ═══════════════════════════════════════════════════════════════════════════
// Variable info (returned by browse and variables requests)
// ═══════════════════════════════════════════════════════════════════════════

// VariableInfo is the JSON structure returned to NATS clients.
type VariableInfo struct {
	ModuleID      string      `json:"moduleId"`
	DeviceID      string      `json:"deviceId"`
	VariableID    string      `json:"variableId"`
	DisplayName   string      `json:"displayName"`
	Value         interface{} `json:"value"`
	Datatype      string      `json:"datatype"`
	OpcuaDatatype string      `json:"opcuaDatatype"`
	Quality       string      `json:"quality"`
	Origin        string      `json:"origin"`
	LastUpdated   int64       `json:"lastUpdated"`
}

// BrowseVariableInfo is the result of browsing a single OPC UA variable.
type BrowseVariableInfo struct {
	NodeID        string `json:"nodeId"`
	DisplayName   string `json:"displayName"`
	Datatype      string `json:"datatype"`
	OpcuaDatatype string `json:"opcuaDatatype"`
}

// CachedVariable holds in-memory state for a discovered/subscribed variable.
type CachedVariable struct {
	NodeID        string
	DisplayName   string
	Datatype      string // "number", "boolean", "string"
	OpcuaDatatype string // e.g. "Double", "Boolean"
	Value         interface{}
	Quality       string // "good", "bad", "unknown"
	LastUpdated   int64
}

// ═══════════════════════════════════════════════════════════════════════════
// Datatype mapping
// ═══════════════════════════════════════════════════════════════════════════

// builtinDataTypes maps OPC UA DataType NodeIDs to human-readable names.
var builtinDataTypes = map[string]string{
	"i=1":  "Boolean",
	"i=2":  "SByte",
	"i=3":  "Byte",
	"i=4":  "Int16",
	"i=5":  "UInt16",
	"i=6":  "Int32",
	"i=7":  "UInt32",
	"i=8":  "Int64",
	"i=9":  "UInt64",
	"i=10": "Float",
	"i=11": "Double",
	"i=12": "String",
	"i=13": "DateTime",
	"i=14": "Guid",
	"i=15": "ByteString",
	"i=16": "XmlElement",
	"i=17": "NodeId",
	"i=19": "StatusCode",
	"i=20": "QualifiedName",
	"i=21": "LocalizedText",
	"i=22": "ExtensionObject",
	"i=24": "BaseDataType",
	"i=26": "Number",
	"i=27": "Integer",
	"i=28": "UInteger",
}

// opcuaToNatsDatatype maps an OPC UA datatype name to "number", "boolean", or "string".
func opcuaToNatsDatatype(opcuaDatatype string) string {
	dt := strings.ToLower(opcuaDatatype)

	if dt == "boolean" {
		return "boolean"
	}

	numericTypes := map[string]bool{
		"sbyte": true, "byte": true, "int16": true, "uint16": true,
		"int32": true, "uint32": true, "int64": true, "uint64": true,
		"float": true, "double": true, "number": true, "integer": true, "uinteger": true,
		"i=1": true, "i=2": true, "i=3": true, "i=4": true, "i=5": true,
		"i=6": true, "i=7": true, "i=8": true, "i=9": true, "i=10": true, "i=11": true,
	}

	if numericTypes[dt] {
		return "number"
	}

	return "string"
}

// extractValue converts a *ua.Variant value to a Go-native type suitable for JSON.
func extractValue(v *ua.Variant) interface{} {
	if v == nil {
		return nil
	}

	val := v.Value()
	if val == nil {
		return nil
	}

	switch tv := val.(type) {
	case bool:
		return tv
	case int8:
		return int64(tv)
	case uint8:
		return int64(tv)
	case int16:
		return int64(tv)
	case uint16:
		return int64(tv)
	case int32:
		return int64(tv)
	case uint32:
		return int64(tv)
	case int64:
		return tv
	case uint64:
		return tv
	case float32:
		return float64(tv)
	case float64:
		return tv
	case string:
		return tv
	case time.Time:
		return tv.UnixMilli()
	case ua.StatusCode:
		return uint32(tv)
	default:
		return fmt.Sprintf("%v", tv)
	}
}

// sanitizeNodeIDForSubject converts a NodeId string to a valid NATS subject segment.
// "ns=2;s=MyTag.SubTag" → "ns_2_s_MyTag_SubTag"
func sanitizeNodeIDForSubject(nodeID string) string {
	r := strings.NewReplacer(".", "_", ";", "_", "=", "_")
	return r.Replace(nodeID)
}
