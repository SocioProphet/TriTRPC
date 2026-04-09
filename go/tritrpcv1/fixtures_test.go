package tritrpcv1

import (
	"bufio"
	"crypto/subtle"
	"encoding/hex"
	"golang.org/x/crypto/chacha20poly1305"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixturePath(name string) string {
	return filepath.Join("..", "..", "fixtures", name)
}

func readPairs(t *testing.T, path string) [][2][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixtures file %s: %v", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	out := make([][2][]byte, 0)
	for sc.Scan() {
		ln := sc.Text()
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		parts := strings.SplitN(ln, " ", 2)
		name := []byte(parts[0])
		b, _ := hex.DecodeString(parts[1])
		out = append(out, [2][]byte{name, b})
	}
	return out
}

func readNonces(t *testing.T, path string) map[string][]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open nonce file %s: %v", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	out := map[string][]byte{}
	for sc.Scan() {
		ln := sc.Text()
		if ln == "" {
			continue
		}
		parts := strings.SplitN(ln, " ", 2)
		key := parts[0]
		b, _ := hex.DecodeString(parts[1])
		out[key] = b
	}
	return out
}

func splitFields(buf []byte) [][]byte {
	fields := [][]byte{}
	off := 0
	for off < len(buf) {
		l, no, err := TLEB3DecodeLen(buf, off)
		if err != nil {
			panic(err)
		}
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
		{"vectors_hex.txt", "vectors_hex.txt.nonces"},
		{"vectors_hex_stream_avrochunk.txt", "vectors_hex_stream_avrochunk.txt.nonces"},
		{"vectors_hex_unary_rich.txt", "vectors_hex_unary_rich.txt.nonces"},
		{"vectors_hex_stream_avronested.txt", "vectors_hex_stream_avronested.txt.nonces"},
		{"vectors_hex_pathB.txt", "vectors_hex_pathB.txt.nonces"},
	}
	key := [32]byte{}
	for _, s := range sets {
		pairs := readPairs(t, fixturePath(s[0]))
		nonces := readNonces(t, fixturePath(s[1]))
		for _, p := range pairs {
			name := string(p[0])
			frame := p[1]
			fields := splitFields(frame)
			if len(fields) < 9 {
				t.Fatalf("too few fields for %s", name)
			}
			env, err := DecodeEnvelope(frame)
			if err != nil {
				t.Fatalf("decode error %s: %v", name, err)
			}
			if hex.EncodeToString(env.Schema) != hex.EncodeToString(SCHEMA_ID_32) {
				t.Fatalf("schema id mismatch %s", name)
			}
			if hex.EncodeToString(env.Context) != hex.EncodeToString(CONTEXT_ID_32) {
				t.Fatalf("context id mismatch %s", name)
			}
			modeTrits, _ := TritUnpack243(env.Mode)
			var modeTrit byte
			if len(modeTrits) > 0 {
				modeTrit = modeTrits[0]
			}
			repacked := BuildEnvelopeWithMode(env.Service, env.Method, env.Payload, env.Aux, env.Tag, env.AeadOn, env.Compress, modeTrit)
			if hex.EncodeToString(repacked) != hex.EncodeToString(frame) {
				t.Fatalf("repack mismatch %s", name)
			}
			flags := fields[3]
			if aeadBit(flags) {
				aad, err := AADBeforeTag(frame, env)
				if err != nil {
					t.Fatalf("aad error %s: %v", name, err)
				}
				tag := env.Tag
				n := nonces[name]
				if len(n) != 24 {
					t.Fatalf("nonce size mismatch %s", name)
				}
				if len(tag) != 16 {
					t.Fatalf("tag size mismatch %s", name)
				}
				a, _ := chacha20poly1305.NewX(key[:])
				strict := os.Getenv("STRICT_AEAD") == "1"
				ct := a.Seal(nil, n, []byte{}, aad)
				computed := ct[len(ct)-16:]
				if subtle.ConstantTimeCompare(computed, tag) != 1 {
					if strict {
						t.Fatalf("strict AEAD tag mismatch for %s", name)
					}
					t.Fatalf("tag mismatch for %s", name)
				}
			}

			if strings.HasSuffix(env.Method, ".REQ") {
				req, err := DecodeHGRequest(env.Payload)
				if err != nil {
					t.Fatalf("decode request %s: %v", name, err)
				}
				recoded, err := EncodeHGRequest(req)
				if err != nil {
					t.Fatalf("re-encode request %s: %v", name, err)
				}
				if hex.EncodeToString(recoded) != hex.EncodeToString(env.Payload) {
					t.Fatalf("HGRequest round-trip mismatch %s", name)
				}
			}
			if strings.HasSuffix(env.Method, ".RSP") {
				resp, err := DecodeHGResponse(env.Payload)
				if err != nil {
					t.Fatalf("decode response %s: %v", name, err)
				}
				recoded, err := EncodeHGResponse(resp)
				if err != nil {
					t.Fatalf("re-encode response %s: %v", name, err)
				}
				if hex.EncodeToString(recoded) != hex.EncodeToString(env.Payload) {
					t.Fatalf("HGResponse round-trip mismatch %s", name)
				}
			}
		}
	}
}
