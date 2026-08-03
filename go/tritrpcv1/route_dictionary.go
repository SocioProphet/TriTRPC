package tritrpcv1

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// RouteEntry maps a direct Handle243 (0..242) to the full route URI it abbreviates.
type RouteEntry struct {
	Handle uint8  `json:"handle"`
	Route  string `json:"route"`
}

// RouteDictionary is the agreed handle->route map that gives a hot frame's route_handle meaning
// (reference/route_dictionary.py). DictionaryID is SHA-256 of the canonical entries — the agreement
// token — so two peers agree iff their tokens match.
type RouteDictionary struct {
	DictionaryID string       `json:"dictionaryId"`
	Entries      []RouteEntry `json:"entries"`
}

func canonicalRouteEntries(entries []RouteEntry) []byte {
	sorted := make([]RouteEntry, len(entries))
	copy(sorted, entries)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Handle < sorted[j].Handle })
	out := []byte{'['}
	for i, e := range sorted {
		if i > 0 {
			out = append(out, ',')
		}
		rj, _ := json.Marshal(e.Route) // matches Python json string escaping
		out = append(out, []byte(fmt.Sprintf(`{"handle":%d,"route":%s}`, e.Handle, rj))...)
	}
	return append(out, ']')
}

func routeDictionaryID(entries []RouteEntry) string {
	sum := sha256.Sum256(canonicalRouteEntries(entries))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// BuildRouteDictionary builds a dictionary from a handle->route map, rejecting out-of-range handles.
func BuildRouteDictionary(mappings map[uint8]string) (RouteDictionary, error) {
	entries := make([]RouteEntry, 0, len(mappings))
	for h, r := range mappings {
		if h > 242 {
			return RouteDictionary{}, fmt.Errorf("handle %d out of Handle243 direct range 0..242", h)
		}
		if r == "" {
			return RouteDictionary{}, fmt.Errorf("empty route for handle %d", h)
		}
		entries = append(entries, RouteEntry{Handle: h, Route: r})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Handle < entries[j].Handle })
	return RouteDictionary{DictionaryID: routeDictionaryID(entries), Entries: entries}, nil
}

// ResolveRoute returns the route for a handle, fail-closed on a tampered token or an unknown handle.
func ResolveRoute(d RouteDictionary, handle uint8) (string, error) {
	if routeDictionaryID(d.Entries) != d.DictionaryID {
		return "", fmt.Errorf("dictionary token does not match its entries (tampered/stale)")
	}
	for _, e := range d.Entries {
		if e.Handle == handle {
			return e.Route, nil
		}
	}
	return "", fmt.Errorf("route_handle %d is not in the agreed dictionary (unresolvable — refused)", handle)
}

// NegotiateRoute returns the agreed dictionary iff both peers' tokens match; else refuses.
func NegotiateRoute(local, remote RouteDictionary) (RouteDictionary, error) {
	if routeDictionaryID(local.Entries) != local.DictionaryID || routeDictionaryID(remote.Entries) != remote.DictionaryID {
		return RouteDictionary{}, fmt.Errorf("a peer's dictionary token does not match its entries")
	}
	if local.DictionaryID != remote.DictionaryID {
		return RouteDictionary{}, fmt.Errorf("dictionary mismatch — peers advertise different handle->route maps (refused)")
	}
	return local, nil
}

// ResolveFrameRoute resolves a hot frame's route_handle against an agreed dictionary — the fabric tie
// between the frame wire (RouteHandle byte) and the negotiated handle->route map.
func ResolveFrameRoute(d RouteDictionary, f HotUnaryFrame) (string, error) {
	return ResolveRoute(d, f.RouteHandle)
}
