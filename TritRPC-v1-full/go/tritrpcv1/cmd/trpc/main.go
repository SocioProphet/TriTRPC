
package main

import (
    "encoding/json"
    "encoding/hex"
    "flag"
    "fmt"
    "io/ioutil"
    "os"

    tr "github.com/example/tritrpcv1"
    "golang.org/x/crypto/chacha20poly1305"
)

func main() {
    if len(os.Args) < 2 {
        fmt.Println("Usage: trpc pack|verify ...")
        os.Exit(1)
    }
    switch os.Args[1] {
    case "pack":
        fs := flag.NewFlagSet("pack", flag.ExitOnError)
        svc := fs.String("service", "", "service")
        method := fs.String("method", "", "method")
        jsonPath := fs.String("json", "", "json path (request/response)")
        nonceHex := fs.String("nonce", "", "24-byte nonce hex")
        keyHex := fs.String("key", "", "32-byte key hex")
        fs.Parse(os.Args[2:])
        if *svc == "" || *method == "" || *jsonPath == "" || *nonceHex == "" || *keyHex == "" {
            fs.Usage(); os.Exit(1)
        }
        jb, _ := ioutil.ReadFile(*jsonPath)
        // For brevity, treat payload as request AddVertex 'a' if not parsing JSON
        payload := buildFromJSON(*method, jb)
        key, _ := hex.DecodeString(*keyHex)
        nonce, _ := hex.DecodeString(*nonceHex)
        var k [32]byte; copy(k[:], key[:32])
        var n [24]byte; copy(n[:], nonce[:24])
        frame, _, _ := tr.EnvelopeWithTag(*svc, *method, payload, nil, k, n)
        fmt.Println(hex.EncodeToString(frame))
    case "verify":
        fs := flag.NewFlagSet("verify", flag.ExitOnError)
        fixtures := fs.String("fixtures", "", "fixtures file")
        nonces := fs.String("nonces", "", "nonces file")
        fs.Parse(os.Args[2:])
        if *fixtures == "" || *nonces == "" { fs.Usage(); os.Exit(1) }
        // reuse test logic by re-implementing minimal verifier here:
        pairs := readPairs(*fixtures)
        nmap := readNonces(*nonces)
        key := [32]byte{}
        for _, p := range pairs {
            name := string(p[0])
            frame := p[1]
            fields := splitFields(frame)
            flags := fields[3]
            if aeadBit(flags) {
                aad, tag := aadAndTag(frame)
                nonce := nmap[name]
                a, _ := chacha20poly1305.NewX(key[:])
                ct := a.Seal(nil, nonce, []byte{}, aad)
                if hex.EncodeToString(ct[len(ct)-16:]) != hex.EncodeToString(tag) {
                    fmt.Println("tag mismatch for", name); os.Exit(2)
                }
            }
        }
        fmt.Println("OK:", *fixtures)
    default:
        fmt.Println("Usage: trpc pack|verify ..."); os.Exit(1)
    }
}

// helpers (copied from tests)

package tritrpcv1

import (
    "encoding/json"
    "bufio"
    "encoding/hex"
    "os"
    "strings"
    "testing"
    "golang.org/x/crypto/chacha20poly1305"
)

func readPairs(path string) [][2][]byte {
    f, _ := os.Open(path); defer f.Close()
    sc := bufio.NewScanner(f)
    out := make([][2][]byte, 0)
    for sc.Scan() {
        ln := sc.Text()
        if ln == "" || strings.HasPrefix(ln, "#") { continue }
        parts := strings.SplitN(ln, " ", 2)
        name := []byte(parts[0])
        b, _ := hex.DecodeString(parts[1])
        out = append(out, [2][]byte{name, b})
    }
    return out
}

func readNonces(path string) map[string][]byte {
    f, _ := os.Open(path); defer f.Close()
    sc := bufio.NewScanner(f)
    out := map[string][]byte{}
    for sc.Scan() {
        ln := sc.Text()
        if ln == "" { continue }
        parts := strings.SplitN(ln, " ", 2)
        key := parts[0]
        b, _ := hex.DecodeString(parts[1])
        out[key] = b
    }
    return out
}

func tleb3DecodeLen(buf []byte, offset int) (val uint64, newOff int) {
    // read one byte; unpack trits; parse tritlets until C=0; compute used bytes by re-pack
    trits := []byte{}
    off := offset
    for {
        b := buf[off]; off++
        ts, _ := TritUnpack243([]byte{b})
        trits = append(trits, ts...)
        if len(trits) < 3 { continue }
        v := uint64(0)
        used := 0
        for j := 0; j < len(trits)/3; j++ {
            c, p1, p0 := trits[3*j], trits[3*j+1], trits[3*j+2]
            digit := uint64(p1)*3 + uint64(p0)
            // base-9 little-endian
            mul := uint64(1)
            for k:=0; k<j; k++ { mul *= 9 }
            v += digit * mul
            if c == 0 {
                used = (j+1)*3
                break
            }
        }
        if used > 0 {
            pack := TritPack243(trits[:used])
            usedBytes := len(pack)
            return v, offset + usedBytes - 1 + (off - offset)
        }
    }
}

func splitFields(buf []byte) [][]byte {
    fields := [][]byte{}
    off := 0
    for off < len(buf) {
        l, no := tleb3DecodeLen(buf, off)
        lo := int(l)
        valStart := no
        valEnd := valStart + lo
        fields = append(fields, buf[valStart:valEnd])
        off = valEnd
    }
    return fields
}

func aeadBit(flags []byte) bool {
    ts, _ := TritUnpack243(flags)
    return len(ts) >= 1 && ts[0] == 2
}

func TestFixturesAEADAndPayloads(t *testing.T) {
    sets := [][2]string{
        {"fixtures/vectors_hex.txt","fixtures/vectors_hex.txt.nonces"},
        {"fixtures/vectors_hex_stream_avrochunk.txt","fixtures/vectors_hex_stream_avrochunk.txt.nonces"},
        {"fixtures/vectors_hex_unary_rich.txt","fixtures/vectors_hex_unary_rich.txt.nonces"},
        {"fixtures/vectors_hex_stream_avronested.txt","fixtures/vectors_hex_stream_avronested.txt.nonces"},
    }
    key := [32]byte{}
    for _, s := range sets {
        pairs := readPairs(s[0])
        nonces := readNonces(s[1])
        for _, p := range pairs {
            name := string(p[0])
            frame := p[1]
            fields := splitFields(frame)
            if len(fields) < 9 { t.Fatalf("too few fields for %s", name) }
            flags := fields[3]
            if aeadBit(flags) {
                // find start of last field (tag)
                off := 0
                lastStart := 0
                idx := 0
                for off < len(frame) {
                    l, no := tleb3DecodeLen(frame, off)
                    lastStart = off
                    off = no + int(l)
                    idx++
                }
                aad := frame[:lastStart]
                tag := fields[len(fields)-1]
                n := nonces[name]
                a, _ := chacha20poly1305.NewX(key[:])
                ct := a.Seal(nil, n, []byte{}, aad)
                if hex.EncodeToString(ct[len(ct)-16:]) != hex.EncodeToString(tag) {
                    t.Fatalf("tag mismatch for %s", name)
                }
                // Payload checks
                if strings.HasSuffix(name, "hyper.v1.AddVertex_a.REQ") || strings.HasSuffix(name, "hyper.v1.AddVertex_a") {
                    payload := fields[8]
                    la := "A"
                    want := EncHGRequestAddVertex("a", &la)
                    if hex.EncodeToString(payload) != hex.EncodeToString(want) {
                        t.Fatalf("payload mismatch %s", name)
                    }
                }
                if strings.HasSuffix(name, "hyper.v1.AddHyperedge_e1_ab.REQ") || strings.HasSuffix(name, "hyper.v1.AddHyperedge_e1_ab") {
                    payload := fields[8]
                    var w int64 = 1
                    want := EncHGRequestAddHyperedge("e1", []string{"a","b"}, &w)
                    if hex.EncodeToString(payload) != hex.EncodeToString(want) {
                        t.Fatalf("payload mismatch %s", name)
                    }
                }
                if strings.HasSuffix(name, "hyper.v1.QueryNeighbors_a_k1.REQ") || strings.HasSuffix(name, "hyper.v1.QueryNeighbors_a_k1") {
                    payload := fields[8]
                    want := EncHGRequestQueryNeighbors("a", 1)
                    if hex.EncodeToString(payload) != hex.EncodeToString(want) {
                        t.Fatalf("payload mismatch %s", name)
                    }
                }
            }
        }
    }
}


/* JSON-driven payload builder (subset) */
func buildFromJSON(method string, jb []byte) []byte {
    type Vtx struct{ Vid, Label string }
    type Edge struct{ Eid string; Members []string; Weight int64 }
    type Req struct {
        Op string
        Vertex *Vtx
        Edge *Edge
        Vid string
        Eid string
        K   int32
    }
    var r Req
    _ = json.Unmarshal(jb, &r)
    switch r.Op {
    case "AddVertex":
        return tr.EncHGRequestAddVertex(r.Vertex.Vid, strPtr(r.Vertex.Label))
    case "AddHyperedge":
        return tr.EncHGRequestAddHyperedge(r.Edge.Eid, r.Edge.Members, &r.Edge.Weight)
    case "QueryNeighbors":
        return tr.EncHGRequestQueryNeighbors(r.Vid, r.K)
    default:
        return tr.EncHGRequestAddVertex("a", strPtr("A"))
    }
}
