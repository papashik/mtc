package mtc

import (
	"crypto/x509/pkix"
	"strconv"
	"strings"

	"github.com/papashik/mtc/pkg/cert"
)

const (
	ProtoPrefix      = "mtc-proto"
	ProtoSep         = ":"
	LandmarkRangeSep = "-"
)

// Proto creates proto string that must be added to client' [tls.Config.NextProtos].
func Proto(caID string, landmarks []cert.Checkpoint) string {
	var proto strings.Builder
	proto.WriteString(ProtoPrefix)
	proto.WriteString(ProtoSep)
	proto.WriteString(cert.CAIDToDN(caID).String())
	proto.WriteString(ProtoSep)
	for _, lm := range landmarks {
		proto.WriteString(strconv.FormatUint(lm.Start, 10))
		proto.WriteString(LandmarkRangeSep)
		proto.WriteString(strconv.FormatUint(lm.End, 10))
		proto.WriteString(ProtoSep)
	}
	return proto.String()
}

// ParseProto finds proto for given CA and extracts landmarks' ranges from it.
func ParseProto(ca pkix.Name, protos []string) []cert.Checkpoint {
	var result []cert.Checkpoint
	for _, p := range protos {
		parts := strings.Split(p, ProtoSep)
		if len(parts) >= 3 && parts[0] == ProtoPrefix && parts[1] == ca.String() {
			for i := 2; i < len(parts); i++ {
				rng := strings.Split(parts[i], LandmarkRangeSep)
				if len(rng) != 2 {
					return result
				}
				start, err := strconv.ParseUint(rng[0], 10, 64)
				if err != nil {
					return result
				}
				end, err := strconv.ParseUint(rng[1], 10, 64)
				if err != nil {
					return result
				}
				result = append(result, cert.Checkpoint{Start: start, End: end})
			}
			return result
		}
	}
	return nil
}
