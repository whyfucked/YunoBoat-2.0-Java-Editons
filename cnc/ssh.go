package main

// ssh.go — SSH front-end for the admin panel. Replaces the raw telnet port:
// operators connect with a normal ssh client (kitty, wezterm, iTerm, any),
// the server authenticates against local.db and hands the session to the same
// Admin state machine the panel always used.
//
//   ssh -p 1234 admin@<host>
//
// The host key is generated once (RSA-4096) and cached next to the database.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

const hostKeyFile = "ssh_host_rsa"

func sshServer() {
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			if ok, _ := store.TryLogin(c.User(), string(pass)); ok {
				return &ssh.Permissions{Extensions: map[string]string{"user": c.User()}}, nil
			}
			return nil, fmt.Errorf("wrong credentials")
		},
		// Banner shown before auth (kitty draws it as the pre-session text).
		BannerCallback: func(c ssh.ConnMetadata) string {
			return "YunoBoat 2.0 — authorised access only\r\n"
		},
	}

	signer, err := loadOrCreateHostKey()
	if err != nil {
		fmt.Printf("\x1b[1;31m[YunoBoat 2.0] ssh host key: %v\x1b[0m\n", err)
		return
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", adminAddr)
	if err != nil {
		fmt.Printf("\x1b[1;31m[YunoBoat 2.0] ssh listener failed on %s: %v\x1b[0m\n", adminAddr, err)
		return
	}
	fmt.Printf("\x1b[1;36m[YunoBoat 2.0] ssh panel listening on %s\x1b[0m\n", adminAddr)

	for {
		raw, err := ln.Accept()
		if err != nil {
			continue
		}
		go serveSSH(raw, cfg)
	}
}

func serveSSH(raw net.Conn, cfg *ssh.ServerConfig) {
	sconn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		_ = raw.Close()
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	// The SSH password callback already verified the credentials — the panel
	// gets the authenticated username and skips its own login prompt.
	authUser := sconn.User()

	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go serveSession(ch, creqs, authUser)
	}
}

// serveSession answers the pty/shell requests and then runs the panel over the
// channel. Window changes are accepted silently so kitty resizes are harmless.
func serveSession(ch ssh.Channel, reqs <-chan *ssh.Request, user string) {
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			_ = req.Reply(true, nil)
		case "window-change":
			_ = req.Reply(true, nil)
		case "shell":
			_ = req.Reply(true, nil)
			conn := &chanConn{ch: ch}
			func() {
				defer func() { _ = recover() }()
				NewAdmin(conn).HandleAuthed(user)
			}()
			_ = ch.Close()
			return
		case "exec":
			_ = req.Reply(false, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
	_ = ch.Close()
}

// ---------------------------------------------------------------------------
// host key
// ---------------------------------------------------------------------------

func loadOrCreateHostKey() (ssh.Signer, error) {
	if b, err := os.ReadFile(hostKeyFile); err == nil {
		if s, err := ssh.ParsePrivateKey(b); err == nil {
			return s, nil
		}
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	pemBytes := pem.EncodeToMemory(block)
	_ = os.WriteFile(hostKeyFile, pemBytes, 0600)
	return ssh.NewSignerFromKey(key)
}

// ---------------------------------------------------------------------------
// net.Conn adapter so the existing Admin code can drive an ssh.Channel
// ---------------------------------------------------------------------------

type chanConn struct {
	ch ssh.Channel
}

func (c *chanConn) Read(p []byte) (int, error)  { return c.ch.Read(p) }
func (c *chanConn) Write(p []byte) (int, error) { return c.ch.Write(p) }
func (c *chanConn) Close() error                { return c.ch.Close() }

func (c *chanConn) LocalAddr() net.Addr  { return sshAddr("ssh-local") }
func (c *chanConn) RemoteAddr() net.Addr { return sshAddr("ssh-client") }

func (c *chanConn) SetDeadline(t time.Time) error      { return nil }
func (c *chanConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *chanConn) SetWriteDeadline(t time.Time) error { return nil }

type sshAddr string

func (a sshAddr) Network() string { return "ssh" }
func (a sshAddr) String() string  { return string(a) }
