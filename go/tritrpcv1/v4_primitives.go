package tritrpcv1

// v4 hot-path primitives — Go port, byte-identical to the Python oracle
// (reference/experimental/tritrpc_requirements_impl_v4). Control243 and State243 each pack five
// trits (canonical fields in {0,1,2}) big-endian into a single value in 0..242 (243 = 3^5), the
// compact control/state byte of the v4 hot frame. Parity is asserted against the shared oracle
// vectors (generated/sample_vectors_v4.json) in v4_primitives_test.go.

import "fmt"

// Control243 fields (profile, lane, evidence, fallback, routefmt), each a trit 0..2.
type Control243 struct {
	Profile  uint8
	Lane     uint8
	Evidence uint8
	Fallback uint8
	RouteFmt uint8
}

// State243 fields (lifecycle, epistemic, novelty, friction, scope), each a trit 0..2.
type State243 struct {
	Lifecycle uint8
	Epistemic uint8
	Novelty   uint8
	Friction  uint8
	Scope     uint8
}

func packTrits5(name string, a, b, c, d, e uint8) (uint8, error) {
	for _, t := range []uint8{a, b, c, d, e} {
		if t > 2 {
			return 0, fmt.Errorf("%s fields must be trits in canonical output", name)
		}
	}
	return ((((a*3)+b)*3+c)*3+d)*3 + e, nil
}

func unpackTrits5(value uint8) (a, b, c, d, e uint8, err error) {
	if value > 242 {
		return 0, 0, 0, 0, 0, fmt.Errorf("byte must be in 0..242")
	}
	w := value
	e = w % 3
	w /= 3
	d = w % 3
	w /= 3
	c = w % 3
	w /= 3
	b = w % 3
	w /= 3
	a = w % 3
	return
}

// Encode packs the Control243 into its canonical 0..242 byte.
func (c Control243) Encode() (uint8, error) {
	return packTrits5("Control243", c.Profile, c.Lane, c.Evidence, c.Fallback, c.RouteFmt)
}

// DecodeControl243 inverts Encode.
func DecodeControl243(value uint8) (Control243, error) {
	a, b, cc, d, e, err := unpackTrits5(value)
	if err != nil {
		return Control243{}, fmt.Errorf("Control243 %w", err)
	}
	return Control243{Profile: a, Lane: b, Evidence: cc, Fallback: d, RouteFmt: e}, nil
}

// Encode packs the State243 into its canonical 0..242 byte.
func (s State243) Encode() (uint8, error) {
	return packTrits5("State243", s.Lifecycle, s.Epistemic, s.Novelty, s.Friction, s.Scope)
}

// DecodeState243 inverts Encode.
func DecodeState243(value uint8) (State243, error) {
	a, b, c, d, e, err := unpackTrits5(value)
	if err != nil {
		return State243{}, fmt.Errorf("State243 %w", err)
	}
	return State243{Lifecycle: a, Epistemic: b, Novelty: c, Friction: d, Scope: e}, nil
}
