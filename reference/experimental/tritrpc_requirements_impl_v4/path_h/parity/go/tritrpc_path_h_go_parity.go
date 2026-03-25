package main

import (
    "crypto/hmac"
    "bytes"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "path/filepath"
)

var magicB2 = []byte{0xF3, 0x2A}
var testTagKey = []byte("TRITRPC_PATH_H_DRAFT_TEST_KEY_32")

var kind243 = map[string]byte{
    "unary_req":    0,
    "unary_rsp":    1,
    "stream_open":  2,
    "stream_data":  3,
    "stream_close": 4,
    "beacon_cap":   5,
    "beacon_intent": 6,
    "beacon_commit": 7,
    "error":         8,
}

var routeH = map[string]byte{
    "PAIR.OPEN":      11,
    "PAIR.HERALD":    12,
    "TELEPORT.BSM3":  13,
    "FRAME.DEFER":    14,
    "WITNESS.REPORT": 15,
}

var pairKind = map[string]byte{"qubit": 0, "qutrit": 1}
var encodingKind = map[string]byte{"unknown": 0, "time-bin": 1, "frequency-bin": 2, "path": 3, "memory-backed": 4}
var subjectKind = map[string]byte{"link": 0, "pair": 1, "path": 2, "memory": 3, "swap": 4}
var clockQuality = map[string]byte{"ok": 0, "degraded": 1, "holdover": 2}

var ctrlMap = map[string][5]int{
    "PAIR.OPEN":      {2, 2, 0, 1, 1},
    "PAIR.HERALD":    {2, 1, 1, 0, 1},
    "TELEPORT.BSM3":  {2, 2, 0, 0, 1},
    "FRAME.DEFER":    {2, 2, 0, 1, 1},
    "WITNESS.REPORT": {2, 2, 2, 0, 1},
}

type fixtureFile struct {
    Meta struct {
        Epoch int    `json:"epoch"`
        Kind  string `json:"kind"`
    } `json:"meta"`
    Fixtures map[string]fixture `json:"fixtures"`
}

type fixture struct {
    Event    string                 `json:"event"`
    Epoch    int                    `json:"epoch"`
    Kind     string                 `json:"kind"`
    RouteH   int                    `json:"route_h"`
    FrameHex string                 `json:"frame_hex"`
    Object   map[string]any         `json:"object"`
    PayloadHex string               `json:"payload_hex"`
}

func tritpack243(trits []int) ([]byte, error) {
    out := make([]byte, 0, len(trits)/5+2)
    i := 0
    for i+5 <= len(trits) {
        val := 0
        for _, t := range trits[i : i+5] {
            if t < 0 || t > 2 {
                return nil, fmt.Errorf("invalid trit %d", t)
            }
            val = val*3 + t
        }
        out = append(out, byte(val))
        i += 5
    }
    k := len(trits) - i
    if k > 0 {
        out = append(out, byte(243+(k-1)))
        val := 0
        for _, t := range trits[i:] {
            if t < 0 || t > 2 {
                return nil, fmt.Errorf("invalid trit %d", t)
            }
            val = val*3 + t
        }
        out = append(out, byte(val))
    }
    return out, nil
}

func tleb3EncodeLen(n int) ([]byte, error) {
    if n < 0 {
        return nil, errors.New("negative length")
    }
    digits := []int{}
    if n == 0 {
        digits = []int{0}
    } else {
        for n > 0 {
            digits = append(digits, n%9)
            n /= 9
        }
    }
    trits := make([]int, 0, len(digits)*3)
    for i, d := range digits {
        c := 0
        if i < len(digits)-1 {
            c = 2
        }
        p1 := d / 3
        p0 := d % 3
        trits = append(trits, c, p1, p0)
    }
    return tritpack243(trits)
}

func s243(n int) ([]byte, error) {
    if n < 0 {
        return nil, errors.New("negative integer")
    }
    if n <= 242 {
        return []byte{byte(n)}, nil
    }
    tail, err := tleb3EncodeLen(n - 243)
    if err != nil {
        return nil, err
    }
    return append([]byte{243}, tail...), nil
}

func h243(n int) ([]byte, error) {
    if n < 0 || n > 242 {
        return nil, fmt.Errorf("handle out of range: %d", n)
    }
    return []byte{byte(n)}, nil
}

func u8(n int) ([]byte, error) {
    if n < 0 || n > 255 {
        return nil, fmt.Errorf("u8 out of range: %d", n)
    }
    return []byte{byte(n)}, nil
}

func u16be(n int) ([]byte, error) {
    if n < 0 || n > 65535 {
        return nil, fmt.Errorf("u16 out of range: %d", n)
    }
    return []byte{byte(n >> 8), byte(n)}, nil
}

func u64be(n uint64) []byte {
    out := make([]byte, 8)
    for i := 7; i >= 0; i-- {
        out[i] = byte(n & 0xff)
        n >>= 8
    }
    return out
}

func bool8(v bool) []byte {
    if v {
        return []byte{1}
    }
    return []byte{0}
}

func ctrl243(profile, lane, evidence, fallback, routefmt int) ([]byte, error) {
    return tritpack243([]int{profile, lane, evidence, fallback, routefmt})
}

func bsm3U8(code string) ([]byte, error) {
    if len(code) != 2 || code[0] < '0' || code[0] > '2' || code[1] < '0' || code[1] > '2' {
        return nil, fmt.Errorf("invalid bsm3_code: %q", code)
    }
    return []byte{byte(int(code[0]-'0')*3 + int(code[1]-'0'))}, nil
}

func testTag(aad []byte) []byte {
    mac := hmac.New(sha256.New, testTagKey)
    mac.Write(aad)
    sum := mac.Sum(nil)
    return sum[:16]
}

func asInt(v any) int {
    switch t := v.(type) {
    case float64:
        return int(t)
    case int:
        return t
    case int64:
        return int(t)
    case json.Number:
        i, _ := t.Int64()
        return int(i)
    default:
        panic(fmt.Sprintf("expected int-like value, got %T", v))
    }
}

func asUint64(v any) uint64 {
    switch t := v.(type) {
    case float64:
        return uint64(t)
    case int:
        return uint64(t)
    case int64:
        return uint64(t)
    case json.Number:
        i, _ := t.Int64()
        return uint64(i)
    default:
        panic(fmt.Sprintf("expected uint64-like value, got %T", v))
    }
}

func asBool(v any) bool {
    b, ok := v.(bool)
    if !ok {
        panic(fmt.Sprintf("expected bool, got %T", v))
    }
    return b
}

func asString(v any) string {
    s, ok := v.(string)
    if !ok {
        panic(fmt.Sprintf("expected string, got %T", v))
    }
    return s
}

func appendAll(dst []byte, parts ...[]byte) []byte {
    for _, p := range parts {
        dst = append(dst, p...)
    }
    return dst
}

func encodePairOpen(obj map[string]any) ([]byte, error) {
    flags := 0
    if asBool(obj["need_memory"]) {
        flags |= 1
    }
    if asBool(obj["need_teleport_ready"]) {
        flags |= 1 << 1
    }
    seq, _ := s243(asInt(obj["seq"]))
    src, _ := h243(asInt(obj["src_site"]))
    dst, _ := h243(asInt(obj["dst_site"]))
    pk, _ := u8(int(pairKind[asString(obj["pair_kind"])]))
    ek, _ := u8(int(encodingKind[asString(obj["encoding_kind"])]))
    tf, _ := u16be(asInt(obj["target_fidelity_milli"]))
    ttl, _ := s243(asInt(obj["ttl_ms"]))
    fb, _ := u8(flags)
    return appendAll(nil, seq, src, dst, pk, ek, tf, ttl, fb), nil
}

func encodePairHerald(obj map[string]any) ([]byte, error) {
    seq, _ := s243(asInt(obj["seq"]))
    pid, _ := h243(asInt(obj["pair_id"]))
    src, _ := h243(asInt(obj["src_site"]))
    dst, _ := h243(asInt(obj["dst_site"]))
    ek, _ := u8(int(encodingKind[asString(obj["encoding_kind"])]))
    hs := bool8(asBool(obj["herald_success"]))
    ts := u64be(asUint64(obj["ts_ns"]))
    fid, _ := u16be(asInt(obj["fidelity_milli"]))
    vis, _ := u16be(asInt(obj["visibility_milli"]))
    ttl, _ := s243(asInt(obj["ttl_ms"]))
    return appendAll(nil, seq, pid, src, dst, ek, hs, ts, fid, vis, ttl), nil
}

func encodeTeleportBSM3(obj map[string]any) ([]byte, error) {
    flags := 0
    if asBool(obj["defer_ok"]) {
        flags |= 1
    }
    if _, ok := obj["mem_id"]; ok {
        flags |= 1 << 1
    }
    seq, _ := s243(asInt(obj["seq"]))
    pid, _ := h243(asInt(obj["pair_id"]))
    basis, _ := u8(asInt(obj["basis_id"]))
    bsm, _ := bsm3U8(asString(obj["bsm3_code"]))
    ts := u64be(asUint64(obj["ts_ns"]))
    fb, _ := u8(flags)
    out := appendAll(nil, seq, pid, basis, bsm, ts, fb)
    if v, ok := obj["mem_id"]; ok {
        mem, _ := h243(asInt(v))
        out = append(out, mem...)
    }
    return out, nil
}

func encodeFrameDefer(obj map[string]any) ([]byte, error) {
    seq, _ := s243(asInt(obj["seq"]))
    pid, _ := h243(asInt(obj["pair_id"]))
    sx, _ := u8(asInt(obj["frame_shift_x"]))
    sz, _ := u8(asInt(obj["frame_shift_z"]))
    epoch, _ := s243(asInt(obj["frame_epoch"]))
    ts := u64be(asUint64(obj["ts_ns"]))
    return appendAll(nil, seq, pid, sx, sz, epoch, ts), nil
}

func encodeWitnessReport(obj map[string]any) ([]byte, error) {
    seq, _ := s243(asInt(obj["seq"]))
    sk, _ := u8(int(subjectKind[asString(obj["subject_kind"])]))
    sid, _ := h243(asInt(obj["subject_id"]))
    delay := u64be(asUint64(obj["delay_ns"]))
    fid, _ := u16be(asInt(obj["fidelity_milli"]))
    vis, _ := u16be(asInt(obj["visibility_milli"]))
    snr, _ := u16be(asInt(obj["snr_milli"]))
    cq, _ := u8(int(clockQuality[asString(obj["clock_quality_code"])]))
    env, _ := h243(asInt(obj["env_ref"]))
    ts := u64be(asUint64(obj["ts_ns"]))
    return appendAll(nil, seq, sk, sid, delay, fid, vis, snr, cq, env, ts), nil
}

func encodePayload(event string, obj map[string]any) ([]byte, error) {
    switch event {
    case "PAIR.OPEN":
        return encodePairOpen(obj)
    case "PAIR.HERALD":
        return encodePairHerald(obj)
    case "TELEPORT.BSM3":
        return encodeTeleportBSM3(obj)
    case "FRAME.DEFER":
        return encodeFrameDefer(obj)
    case "WITNESS.REPORT":
        return encodeWitnessReport(obj)
    default:
        return nil, fmt.Errorf("unknown event %s", event)
    }
}

func encodeFrame(event string, obj map[string]any, epoch int, kind string) ([]byte, error) {
    ctrlCfg, ok := ctrlMap[event]
    if !ok {
        return nil, fmt.Errorf("missing control config for %s", event)
    }
    ctrl, err := ctrl243(ctrlCfg[0], ctrlCfg[1], ctrlCfg[2], ctrlCfg[3], ctrlCfg[4])
    if err != nil {
        return nil, err
    }
    payload, err := encodePayload(event, obj)
    if err != nil {
        return nil, err
    }
    ep, err := s243(epoch)
    if err != nil {
        return nil, err
    }
    rh, err := h243(int(routeH[event]))
    if err != nil {
        return nil, err
    }
    pl, err := s243(len(payload))
    if err != nil {
        return nil, err
    }
    kb, err := u8(int(kind243[kind]))
    if err != nil {
        return nil, err
    }
    front := appendAll(nil, magicB2, ctrl, kb, ep, rh, pl, payload)
    return append(front, testTag(front)...), nil
}

func defaultFixturePath() string {
    exe, err := os.Executable()
    if err != nil {
        return "tritrpc_path_h_fixtures.json"
    }
    return filepath.Join(filepath.Dir(exe), "tritrpc_path_h_fixtures.json")
}

func main() {
    fixturePath := defaultFixturePath()
    if len(os.Args) > 1 {
        fixturePath = os.Args[1]
    }
    raw, err := os.ReadFile(fixturePath)
    if err != nil {
        fmt.Fprintf(os.Stderr, "error reading fixtures: %v\n", err)
        os.Exit(2)
    }
    dec := json.NewDecoder(bytes.NewReader(raw))
    dec.UseNumber()
    var ff fixtureFile
    if err := dec.Decode(&ff); err != nil {
        fmt.Fprintf(os.Stderr, "error parsing fixtures: %v\n", err)
        os.Exit(2)
    }

    failures := 0
    for name, fx := range ff.Fixtures {
        encoded, err := encodeFrame(fx.Event, fx.Object, fx.Epoch, fx.Kind)
        if err != nil {
            fmt.Fprintf(os.Stderr, "%s: encode error: %v\n", name, err)
            failures++
            continue
        }
        got := hex.EncodeToString(encoded)
        if got != fx.FrameHex {
            fmt.Printf("FAIL %s\n  want: %s\n  got:  %s\n", name, fx.FrameHex, got)
            failures++
        } else {
            fmt.Printf("PASS %s\n", name)
        }
    }
    if failures > 0 {
        os.Exit(1)
    }
}

