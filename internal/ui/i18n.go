package ui

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

//go:embed i18n/*.json
var i18nFS embed.FS

// Supported interface languages; the first is the fallback.
var languages = []string{"en", "tr"}

const langCookie = "lang"

// catalog maps language -> message key -> text.
type catalog map[string]map[string]string

func loadCatalog() (catalog, error) {
	cat := catalog{}
	for _, lang := range languages {
		b, err := i18nFS.ReadFile("i18n/" + lang + ".json")
		if err != nil {
			return nil, err
		}
		m := map[string]string{}
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("i18n/%s.json: %w", lang, err)
		}
		cat[lang] = m
	}
	return cat, nil
}

// translator returns a lookup that formats the message with args (fmt
// verbs) and falls back to the key itself so a missing message is visible
// on the page and caught by TestI18nKeysComplete.
func translator(m map[string]string) func(key string, args ...any) string {
	return func(key string, args ...any) string {
		msg, ok := m[key]
		if !ok {
			return key
		}
		if len(args) > 0 {
			return fmt.Sprintf(msg, args...)
		}
		return msg
	}
}

func supportedLang(l string) bool {
	for _, s := range languages {
		if s == l {
			return true
		}
	}
	return false
}

// negotiateLang picks the language: lang cookie, then Accept-Language (by
// q value, then order), then English.
func negotiateLang(r *http.Request) string {
	if c, err := r.Cookie(langCookie); err == nil && supportedLang(c.Value) {
		return c.Value
	}
	type pref struct {
		lang string
		q    float64
	}
	var prefs []pref
	for _, part := range strings.Split(r.Header.Get("Accept-Language"), ",") {
		tag, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		if v, ok := strings.CutPrefix(strings.TrimSpace(params), "q="); ok {
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				continue
			}
			q = f
		}
		base, _, _ := strings.Cut(strings.ToLower(tag), "-")
		if supportedLang(base) && q > 0 {
			prefs = append(prefs, pref{base, q})
		}
	}
	sort.SliceStable(prefs, func(a, b int) bool { return prefs[a].q > prefs[b].q })
	if len(prefs) > 0 {
		return prefs[0].lang
	}
	return languages[0]
}
