package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/id"
	"github.com/gopcua/opcua/ua"
)

// BrowseProgressFunc is called during browse to report progress.
type BrowseProgressFunc func(totalDiscovered int, currentNodeID string, message string)

// browseAddressSpace recursively walks the OPC UA address space starting from
// startNodeID, collecting Variable nodes with their DataType and display names.
func browseAddressSpace(
	ctx context.Context,
	client *opcua.Client,
	startNodeID string,
	maxDepth int,
	progress BrowseProgressFunc,
) ([]BrowseVariableInfo, error) {
	var discovered []BrowseVariableInfo
	visited := make(map[string]bool)
	dataTypeCache := make(map[string]string)
	nodesVisited := 0
	lastProgressTime := time.Now()

	var browseRecursive func(nodeID string, depth int) error
	browseRecursive = func(nodeID string, depth int) error {
		if depth > maxDepth {
			return nil
		}
		if visited[nodeID] {
			return nil
		}
		visited[nodeID] = true
		nodesVisited++

		// Report progress every 5 seconds
		if progress != nil && time.Since(lastProgressTime) > 5*time.Second {
			lastProgressTime = time.Now()
			progress(
				len(discovered), nodeID,
				fmt.Sprintf("Browsing... %d nodes visited, %d variables found (depth %d)",
					nodesVisited, len(discovered), depth),
			)
		}

		parsedID, err := ua.ParseNodeID(nodeID)
		if err != nil {
			logDebug("opcua:browse", "Invalid NodeID %s: %v", nodeID, err)
			return nil
		}

		req := &ua.BrowseRequest{
			NodesToBrowse: []*ua.BrowseDescription{
				{
					NodeID:          parsedID,
					BrowseDirection: ua.BrowseDirectionForward,
					IncludeSubtypes: true,
					ReferenceTypeID: ua.NewNumericNodeID(0, id.HierarchicalReferences),
					ResultMask:      uint32(ua.BrowseResultMaskAll),
				},
			},
		}

		resp, err := client.Browse(ctx, req)
		if err != nil {
			logDebug("opcua:browse", "Browse failed for %s: %v", nodeID, err)
			return nil
		}

		if len(resp.Results) == 0 {
			return nil
		}

		result := resp.Results[0]
		refs := result.References

		// Handle continuation points
		for result.ContinuationPoint != nil && len(result.ContinuationPoint) > 0 {
			nextResp, err := client.BrowseNext(ctx, &ua.BrowseNextRequest{
				ContinuationPoints: [][]byte{result.ContinuationPoint},
			})
			if err != nil {
				logDebug("opcua:browse", "BrowseNext failed for %s: %v", nodeID, err)
				break
			}
			if len(nextResp.Results) == 0 {
				break
			}
			result = nextResp.Results[0]
			refs = append(refs, result.References...)
		}

		for _, ref := range refs {
			childNodeID := ref.NodeID.NodeID.String()

			if ref.NodeClass == ua.NodeClassVariable {
				// Read DataType attribute
				readReq := &ua.ReadRequest{
					NodesToRead: []*ua.ReadValueID{
						{
							NodeID:      ref.NodeID.NodeID,
							AttributeID: ua.AttributeIDDataType,
						},
					},
				}

				readResp, err := client.Read(ctx, readReq)
				if err != nil {
					logDebug("opcua:browse", "Failed to read DataType for %s: %v", childNodeID, err)
					continue
				}

				opcuaDatatype := "String"
				if len(readResp.Results) > 0 && readResp.Results[0].Status == ua.StatusOK {
					dtNodeID := readResp.Results[0].Value
					if dtNodeID != nil {
						dtStr := fmt.Sprintf("%v", dtNodeID.Value())
						opcuaDatatype = resolveDataTypeName(ctx, client, dtStr, dataTypeCache)
					}
				}

				displayName := childNodeID
				if ref.DisplayName != nil && ref.DisplayName.Text != "" {
					displayName = ref.DisplayName.Text
				} else if ref.BrowseName != nil && ref.BrowseName.Name != "" {
					displayName = ref.BrowseName.Name
				}

				natsDatatype := opcuaToNatsDatatype(opcuaDatatype)

				discovered = append(discovered, BrowseVariableInfo{
					NodeID:        childNodeID,
					DisplayName:   displayName,
					Datatype:      natsDatatype,
					OpcuaDatatype: opcuaDatatype,
				})

				if progress != nil && len(discovered)%10 == 0 {
					lastProgressTime = time.Now()
					progress(len(discovered), childNodeID,
						fmt.Sprintf("Discovered %d variables (%d nodes visited)...",
							len(discovered), nodesVisited))
				}
			}

			// Recurse into Object and View nodes
			if ref.NodeClass == ua.NodeClassObject || ref.NodeClass == ua.NodeClassView {
				if err := browseRecursive(childNodeID, depth+1); err != nil {
					return err
				}
			}
		}

		return nil
	}

	logInfo("opcua:browse", "Starting address space browse from %s (maxDepth: %d)", startNodeID, maxDepth)
	if err := browseRecursive(startNodeID, 0); err != nil {
		return nil, err
	}
	logInfo("opcua:browse", "Browse complete: %d variables discovered", len(discovered))

	if progress != nil {
		progress(len(discovered), startNodeID,
			fmt.Sprintf("Browse complete: %d variables", len(discovered)))
	}

	return discovered, nil
}

// resolveDataTypeName resolves a DataType NodeID to a human-readable name,
// using a cache to avoid repeated reads.
func resolveDataTypeName(ctx context.Context, client *opcua.Client, dataTypeNodeID string, cache map[string]string) string {
	// Normalize — strip ns=0; prefix
	normalized := strings.Replace(dataTypeNodeID, "ns=0;", "", 1)

	if name, ok := builtinDataTypes[normalized]; ok {
		return name
	}
	if name, ok := cache[dataTypeNodeID]; ok {
		return name
	}

	// Try to read the BrowseName from the server
	parsedID, err := ua.ParseNodeID(dataTypeNodeID)
	if err != nil {
		cache[dataTypeNodeID] = dataTypeNodeID
		return dataTypeNodeID
	}

	readReq := &ua.ReadRequest{
		NodesToRead: []*ua.ReadValueID{
			{
				NodeID:      parsedID,
				AttributeID: ua.AttributeIDBrowseName,
			},
		},
	}

	resp, err := client.Read(ctx, readReq)
	if err == nil && len(resp.Results) > 0 && resp.Results[0].Status == ua.StatusOK {
		if qn, ok := resp.Results[0].Value.Value().(*ua.QualifiedName); ok && qn.Name != "" {
			cache[dataTypeNodeID] = qn.Name
			return qn.Name
		}
	}

	cache[dataTypeNodeID] = dataTypeNodeID
	return dataTypeNodeID
}
