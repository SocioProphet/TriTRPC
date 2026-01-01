
package tritrpcv1

import (
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
                strict := os.Getenv("STRICT_AEAD") == "1"
                ct := a.Seal(nil, n, []byte{}, aad)
                if hex.EncodeToString(ct[len(ct)-16:]) != hex.EncodeToString(tag) {
                    if strict { t.Fatalf("strict AEAD tag mismatch for %s", name) }
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
