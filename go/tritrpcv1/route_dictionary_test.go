package tritrpcv1

import "testing"

// TestRouteDictionaryParity: the Go dictionary id matches the Python reference id byte-for-byte.
func TestRouteDictionaryParity(t *testing.T) {
	d, err := BuildRouteDictionary(map[uint8]string{7: "route://agentplane/executor", 9: "route://agentplane/planner"})
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:0d571917236bbe69678cae09da55763eca36d456942429481a71e50d8b45ae60"
	if d.DictionaryID != want {
		t.Fatalf("dictionary id parity: got %s want %s", d.DictionaryID, want)
	}
}

// TestResolveFrameRoute: a hot frame's route_handle resolves against the agreed dictionary; an
// unknown handle and a tampered dictionary are refused (fabric tie + fail-closed).
func TestResolveFrameRoute(t *testing.T) {
	d, _ := BuildRouteDictionary(map[uint8]string{7: "route://agentplane/executor", 9: "route://agentplane/planner"})
	f := HotUnaryFrame{RouteHandle: 7}
	got, err := ResolveFrameRoute(d, f)
	if err != nil || got != "route://agentplane/executor" {
		t.Fatalf("frame route resolve: got %q err %v", got, err)
	}
	if _, err := ResolveFrameRoute(d, HotUnaryFrame{RouteHandle: 200}); err == nil {
		t.Fatal("an unknown route_handle must be refused")
	}
	tampered := d
	tampered.Entries = append([]RouteEntry{{Handle: 7, Route: "route://evil"}}, d.Entries[1])
	if _, err := ResolveRoute(tampered, 7); err == nil {
		t.Fatal("a tampered dictionary (stale token) must be refused")
	}
}

// TestNegotiateRoute: matching dictionaries agree; a divergent one is refused.
func TestNegotiateRoute(t *testing.T) {
	a, _ := BuildRouteDictionary(map[uint8]string{7: "route://x"})
	b, _ := BuildRouteDictionary(map[uint8]string{7: "route://x"})
	if _, err := NegotiateRoute(a, b); err != nil {
		t.Fatalf("matching dictionaries must agree: %v", err)
	}
	c, _ := BuildRouteDictionary(map[uint8]string{7: "route://different"})
	if _, err := NegotiateRoute(a, c); err == nil {
		t.Fatal("divergent dictionaries must be refused")
	}
}
