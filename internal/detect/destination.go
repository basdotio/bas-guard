// SPDX-License-Identifier: MIT
package detect

import (
	"regexp"
	"slices"
	"strings"
)

// Destination consistency. A file that reads DEEPL_API_KEY and sends it to api.deepl.com
// looks byte-for-byte like one that sends it to an attacker; the difference is whether the
// destination IS the credential's own service. When every readable, non-loopback destination in a
// file carries the service token of a named credential the file reads, EXFIL-001 drops to the
// EXFIL-002 band — data left the machine, but for the place the credential exists to reach. This is
// deliberately conservative: it never downgrades a whole-environment dump (which names no service),
// a chain with any unreadable destination, or one whose destinations do not all match. Measured on
// the corpus: 15 of 74 benign EXFIL-001 samples downgrade, 0 of 26 malicious.

// secretIdentRE finds identifier-shaped names with at least one separator, e.g. DEEPL_API_KEY,
// WALLET_PRIVATE_KEY, github.token. A name must also carry a secret word (secretNamePat) to count.
var secretIdentRE = regexp.MustCompile(`[A-Za-z][A-Za-z0-9]*(?:[_.][A-Za-z0-9]+)+`)

// genericToken are the parts of a credential name or a host that name no service — dropping them is
// what stops `API` in `api.deepl.com` from matching `X_API_KEY`, or `key` from matching everything.
var genericToken = map[string]bool{
	"api": true, "com": true, "net": true, "org": true, "io": true, "www": true, "co": true,
	"dev": true, "app": true, "cloud": true, "ai": true, "v1": true, "v2": true, "v3": true,
	"http": true, "https": true, "key": true, "token": true, "secret": true, "password": true,
	"passwd": true, "apikey": true, "credential": true, "credentials": true, "bearer": true,
	"oauth": true, "auth": true, "access": true, "private": true, "my": true, "the": true,
	"get": true, "id": true, "url": true, "base": true, "default": true, "pro": true, "env": true,
	// Words that say what KIND of credential it is, who holds it or where it is used, never whose
	// service it is for (P-145). Each was a host an attacker could register or already owns:
	// WEBHOOK_SECRET sent to webhook.site, SLACK_BOT_TOKEN to bot.xyz and
	// GITHUB_PERSONAL_ACCESS_TOKEN to personal.dev all read as a key sent home.
	"bot": true, "user": true, "client": true, "service": true, "account": true, "personal": true,
	"admin": true, "master": true, "root": true, "webhook": true, "hook": true, "signing": true,
	"refresh": true, "session": true, "login": true, "application": true, "project": true,
	"team": true, "workspace": true, "prod": true, "production": true, "staging": true, "test": true,
	"live": true, "sandbox": true, "public": true, "internal": true, "server": true, "cli": true,
	"sdk": true, "mcp": true, "agent": true, "database": true, "smtp": true, "mail": true,
	"email": true, "web": true, "site": true, "host": true, "registry": true,
}

// serviceTokens splits a name on _ - . into lowercase parts, keeping the ones longer than two
// characters that are not generic. `DEEPL_API_KEY` -> {deepl}; `TOKEN` -> {} (nothing to vouch for).
func serviceTokens(name string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(strings.ToLower(name), func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	}) {
		if len(p) > 2 && !genericToken[p] {
			out = append(out, p)
		}
	}
	return out
}

// credentialServiceTokens returns the service tokens of every NAMED secret on a line. A
// whole-environment dump (`dict(os.environ)`, `printenv`) contains no such name and yields nothing,
// which is why it can never license a downgrade.
func credentialServiceTokens(line string) []string {
	var out []string
	for _, name := range secretIdentRE.FindAllString(line, -1) {
		if secretNameRE.MatchString(name) {
			out = append(out, ownerTokens(serviceTokens(name))...)
		}
	}
	return out
}

// ownerTokens returns the tokens of ONE credential's name that may name its service. When the name
// carries a service the table knows (serviceDomains, P-145), the credential is that service's and
// the rest of its name describes it: GITHUB_ENTERPRISE_TOKEN is a GitHub token, and a host called
// `enterprise.<anything>` has no claim to it. A name with two known services keeps both
// (AZURE_OPENAI_API_KEY). A name the table knows nothing in keeps every token, as before.
func ownerTokens(tokens []string) []string {
	var known []string
	for _, t := range tokens {
		if _, ok := serviceDomains[t]; ok {
			known = append(known, t)
		}
	}
	if len(known) > 0 {
		return known
	}
	return tokens
}

// hostedSuffix are second-level domains that hand out names to anyone — a Tailscale tailnet, a
// GitHub Pages site, a Vercel deployment — so the platform's own label can never vouch for the
// party: `evil.github.io` is evil's, not GitHub's, and a GITHUB_TOKEN sent there is exfiltration.
var hostedSuffix = map[string]bool{
	"ts.net": true, "github.io": true, "gitlab.io": true, "vercel.app": true, "netlify.app": true,
	"herokuapp.com": true, "pages.dev": true, "workers.dev": true, "onrender.com": true,
	"railway.app": true, "fly.dev": true, "azurewebsites.net": true, "cloudfunctions.net": true,
	"amazonaws.com": true, "run.app": true, "web.app": true, "firebaseapp.com": true,
	"ngrok.io": true, "ngrok-free.app": true, "trycloudflare.com": true, "repl.co": true,
}

// ccSecondLevel are the labels that stand between an organisation's own label and a two-letter
// country code: `coles.com.au`, `mlit.go.jp`, `bbc.co.uk`. With one of them in that position the
// organisation's label is the third from the end, not the second.
var ccSecondLevel = map[string]bool{
	"co": true, "com": true, "org": true, "net": true, "gov": true, "go": true, "ac": true, "edu": true,
	"or": true, "ne": true, "mil": true, "gob": true, "gouv": true, "govt": true, "nom": true, "sch": true,
}

// hostMatchesService reports whether the host is the credential service's own: its REGISTRABLE
// label — the one directly left of the top-level domain, or of a country's second level
// (`mlit.go.jp`) — is exactly a service token. `api.deepl.com` is deepl's; so is `deepl.com`.
//
// Only that label is the owner's to choose. Every label to its left is chosen by whoever holds the
// domain, so `stripe.evil.net`, `stripe.com-api.evil.net` and `api.openai.com.evil.net` are all
// evil.net's, however much of the service's name they spell. Until P-144 any label could vouch
// unless it was followed by a TLD-like label, on the strength of two benign hosts where the
// credential is named after a tenant or a product of the domain (`purdue.brightspace.com` for
// PURDUE_PASSWORD, `otx.alienvault.com` for OTX_API_KEY): those two no longer match, and neither
// does anybody's subdomain named after somebody else's service.
//
// Under a hosted platform's suffix (hostedSuffix) nothing matches: the platform's own label is not
// the party, and the label left of it is a name the platform hands to whoever asks first —
// `stripe.vercel.app` is not Stripe's because it says so.
//
// For a service the table of known services lists (serviceDomains, P-145) the label is not enough:
// the registrable DOMAIN must be one of the service's, so `stripe.xyz` is not Stripe's.
//
// Matching is exact: a label that merely begins with the token (`openaievil.net`) is a lookalike.
// The RAW host is used by the caller, so a homoglyph domain (`dееpl.com` with Cyrillic е) does not
// fold into the ASCII service name and cannot buy a downgrade.
func hostMatchesService(host string, services map[string]bool) bool {
	labels := strings.Split(strings.ToLower(strings.TrimSpace(host)), ".")
	n := len(labels)
	if n < 2 {
		return false
	}
	if n >= 3 && hostedSuffix[labels[n-2]+"."+labels[n-1]] {
		return false
	}
	registrable := n - 2
	if n >= 3 && len(labels[n-1]) == 2 && ccSecondLevel[labels[n-2]] {
		registrable = n - 3
	}
	label := labels[registrable]
	if !services[label] {
		return false
	}
	// A service the table knows vouches only under its own domains: `stripe.com`, not the same
	// name under a suffix anyone may register (P-145, serviceDomains). A service it does not know
	// is matched by its name alone, as before.
	if domains, known := serviceDomains[label]; known {
		return slices.Contains(domains, strings.Join(labels[registrable:], "."))
	}
	return true
}

// A destination written as a variable — `curl "$API/credits"`, fetch(`${BASE}/v1`), `requests.get(url)`,
// `API_BASE + "/images"` — used to make the whole file unverifiable, and with it every skill whose
// one base URL is set at the top and used below, which is how most real scripts are written. The
// rule now resolves ONE level inside the same file, the way SUP-006 resolves a shell variable: if
// the file assigns the variable an http(s) literal, that literal's host is the destination. A
// variable the file never assigns a URL (a parameter, a field of a response) stays unreadable (P-061).
//
// The literal vouches for the host it spells, and only for that host (P-143). A base that ends at
// its host — `API=https://api.deepl.com`, with or without a port — is continued by whatever the
// line puts after the name, and unless that begins a path the host that is contacted is another
// one: `${API}.evil.net`, `${API}-x.evil.net`, `${API}evil.net` (the host api.deepl.comevil.net),
// `${API}@evil.net` (the literal becomes the userinfo of evil.net), `API + ".evil.net/x"`,
// `API + suffix`. None of those is resolved. A base that already holds a path
// (`https://api.deepl.com/v2`) cannot be continued into another host and resolves whatever follows.
// Before P-143 only a `.` straight after `$NAME` or `{NAME}` was refused: every other spelling read
// as the service's own host, and with a loopback base as a request that stays on the machine.

// urlAssignRE: NAME = … https://host…, in shell (`API=${API:-https://x}`, `API="https://x"`),
// JavaScript (`const API = process.env.X || 'https://x'`), Python (`API_BASE = os.environ.get("X", "https://x")`)
// and YAML-ish (`url: https://x`). The URL may follow other text on the line, but not another
// assignment: a line assigning two names is skipped by the non-greedy class stopping at `=`.
var urlAssignRE = regexp.MustCompile(`(?i)(?:^|[\s;{(,])(?:export\s+|const\s+|let\s+|var\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(?:\$\{[A-Za-z_][A-Za-z0-9_]*:-)?[^\n]*?(https?://[^\s"'<>(),;}` + "`" + `]+)`)

// The variables a destination expression refers to, each captured with the text that follows it on
// the line, which decides whether the reference is the whole host (continuesHost). Four spellings:
// `$NAME`, `${NAME}` and `{NAME}` (shell, JS templates, Python f-strings), the first argument of a
// client call (`fetch(url,`, `requests.get(url)`, `get(API + …`), and a name concatenated with a
// string that begins a path (`API_BASE + "/x"`).
var (
	urlVarDollarRE = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)(.*)`)
	urlVarBracedRE = regexp.MustCompile(`\$?\{([A-Za-z_][A-Za-z0-9_]*)\}(.*)`)
	urlVarArgRE    = regexp.MustCompile(`(?i)(?:fetch|get|post|put|patch|urlopen|Request|request)\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*([,)+].*)`)
	urlVarConcatRE = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*)\s*\+\s*["'` + "`" + `]/`)
)

// urlAssigned is what a file assigns one name: the host of the http(s) literal, and whether the
// literal ends at that host (open) rather than going on into a path, a query or a fragment.
type urlAssigned struct {
	host string
	open bool
}

// urlTable is a file's NAME -> assigned URL table (urlAssignments).
type urlTable map[string]urlAssigned

// urlAssignments returns what every same-file URL assignment gives its name. Loopback hosts are
// kept (so a `BASE=http://localhost:8000` resolves on-box) and the caller screens them.
func urlAssignments(text string) urlTable {
	var out urlTable
	for _, line := range strings.Split(text, "\n") {
		for _, m := range urlAssignRE.FindAllStringSubmatch(line, -1) {
			h := urlHost(m[2])
			if h == "?" {
				continue
			}
			if out == nil {
				out = urlTable{}
			}
			if _, dup := out[m[1]]; !dup {
				_, after, _ := strings.Cut(m[2], "://")
				out[m[1]] = urlAssigned{host: h, open: !strings.ContainsAny(after, "/?#")}
			}
		}
	}
	return out
}

// continuesHost reports whether the text after a reference to an OPEN base carries the host on
// instead of ending it. The host ends at a path, query or fragment, at the end of its string or of
// the line, and at a port. Anything else joins the name's value into a longer authority: more name
// characters or labels, an `@` that turns everything before it into userinfo, another reference
// whose value the file does not show, or — after the string closes — a concatenation with
// something that does not begin a path.
func continuesHost(after string) bool {
	rest := strings.TrimLeft(after, "}") // `${NAME}` as urlVarDollarRE leaves it
	end := strings.IndexAny(rest, "/?#\"'` \t)],;&|<>\\")
	authority, tail := rest, ""
	if end >= 0 {
		authority, tail = rest[:end], rest[end:]
	}
	if authority != "" {
		// A port is the one thing that may follow a host inside its authority.
		port, ok := strings.CutPrefix(authority, ":")
		if !ok || port == "" || strings.Trim(port, "0123456789") != "" {
			return true
		}
	}
	if tail == "" || !strings.ContainsRune("\"'`", rune(tail[0])) {
		return false
	}
	// The string closed here. `+` after it continues the value with another operand.
	operand, concat := strings.CutPrefix(strings.TrimSpace(tail[1:]), "+")
	return concat && !beginsPath(operand)
}

// beginsPath reports whether a concatenated operand is a string literal that begins a path, a query
// or a fragment: the one operand that cannot carry a host on.
func beginsPath(operand string) bool {
	operand = strings.TrimSpace(operand)
	return len(operand) >= 2 && strings.ContainsRune("\"'`", rune(operand[0])) && strings.ContainsRune("/?#", rune(operand[1]))
}

// resolvedHosts returns the hosts an unreadable destination line resolves to through the file's
// assignments, or nothing. A reference to an open base that the line continues into another host is
// not resolved (continuesHost).
func resolvedHosts(line string, assigns urlTable) []string {
	if len(assigns) == 0 {
		return nil
	}
	var out []string
	add := func(name string, continued bool) {
		if a, ok := assigns[name]; ok && !(a.open && continued) {
			out = append(out, a.host)
		}
	}
	// Each reference is read with the rest of the line after it; the patterns are greedy to the
	// line's end, so the search restarts inside what followed to find the next reference.
	for _, re := range []*regexp.Regexp{urlVarDollarRE, urlVarBracedRE} {
		for rest := line; ; {
			m := re.FindStringSubmatch(rest)
			if m == nil {
				break
			}
			add(m[1], continuesHost(m[2]))
			rest = m[2]
		}
	}
	for rest := line; ; {
		m := urlVarArgRE.FindStringSubmatch(rest)
		if m == nil {
			break
		}
		// `get(NAME,` and `get(NAME)` end the value; `get(NAME + …` continues it unless a path follows.
		operand, concat := strings.CutPrefix(m[2], "+")
		add(m[1], concat && !beginsPath(operand))
		rest = m[2]
	}
	for _, m := range urlVarConcatRE.FindAllStringSubmatch(line, -1) {
		add(m[1], false)
	}
	return out
}

// CredentialGoesHome reports whether a file that reads a NAMED credential sends it only where that
// credential belongs: every non-loopback destination the file names (after one level of same-file
// resolution) carries the service token of a credential the file reads, or every destination is
// loopback. It is the judge's question on the server pass (P-062): a tool that reads
// WEATHER_API_KEY to call api.weather.com has not read a credential in the sense `credential-read`
// means, and the model cannot tell that from the excerpt it is shown. The answer is computed over
// the FULL file, by the chain EXFIL-001 runs in its judge-side reading (homeChain, chainreadings.go:
// every URL literal is a destination, where the rules count one only in a script that can send),
// so a foreign URL anywhere in the file refuses the downgrade. A file that reads no named credential, or names no destination, answers false — the
// absence of a chain is not a verdict about one.
func CredentialGoesHome(path, text string) bool {
	c := replay(homeChain(text), path, text)
	if !c.cred || !c.net || len(c.credService) == 0 {
		return false
	}
	if !c.netOffBox {
		return true
	}
	return c.destConsistent()
}

// overreachRE is a credential source no server owns: another program's secrets on disk (SSH keys,
// cloud and container credentials, .netrc), the system's account and network files, another
// process's environment or anything else under /proc and /sys, a cloud metadata service, the user
// database, the keychain, a browser's cookie store, a hidden file in a world-writable temp directory
// (where a stolen credential is kept). Reading its OWN configuration — os.getenv("STRIPE_API_KEY"), a settings object,
// load_dotenv() — is what an MCP server is configured with and is none of these.
var overreachRE = regexp.MustCompile(`(?i)\.ssh/|\.aws/credentials|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|authorized_keys|\.kube/config|\.docker/config\.json|\.git-credentials|\.netrc\b` +
	`|/etc/(?:passwd|shadow|gshadow|sudoers|group|hosts|resolv\.conf|hostname)\b|/proc/|/sys/|/environ\b|/(?:tmp|var/tmp|dev/shm)/\.` +
	`|169\.254\.169\.254|metadata\.google\.internal|/latest/meta-data|\bgetpw(?:all|nam|uid)\b|/var/log/` +
	`|\bsecurity\s+find-(?:generic|internet)-password|\bkeychain\b|/Cookies\b|Login Data`)

// CredentialOverreach reports whether a file reaches for a credential beyond its own configuration
// (P-098): any code line names an overreachRE source, or enumerates the whole environment — every
// key, the way EXFIL-004 means it, not the child-process copy (`{...process.env, X}`,
// `os.environ.copy()` handed to a subprocess) that the credential leg already exempts. It is the
// server pass's question for `credential-read`: on 543 benign server trees, 46 of the 63 the judge
// alone flagged high were a server reading its own key or password to log in to its own service;
// on Cisco's 127 malicious servers the credential reads were the environment, /etc/passwd,
// /proc/<pid>/environ and the metadata service. Over the whole file, like CredentialGoesHome: the
// quote is often a function's signature and the path it reads is a constant elsewhere in the file.
func CredentialOverreach(path, text string) bool {
	comments := commentOnlyLines(langForFile(path), text)
	for _, ll := range logicalLines(langForFile(path), text, comments) {
		if ll.comment {
			continue
		}
		for _, v := range [2]string{ll.norm, ll.raw} {
			if overreachRE.MatchString(v) {
				return true
			}
			whole := envWholeRE.MatchString(v) || envDumpShellRE.MatchString(v)
			childCopy := envChildCopyRE.MatchString(v) || strings.Contains(v, "environ.copy()")
			if whole && !(childCopy && !envLeavesRE.MatchString(v)) {
				return true
			}
		}
	}
	return false
}

// credNameRE is a credential named in code without an environment read — `settings.password`,
// `config["api_key"]` — which the chain's credential leg does not count. CredentialSentElsewhere
// counts it, because a settings object is how a server holds the secret it would send.
var credNameRE = regexp.MustCompile(`(?i)\b\w*(?:password|passwd|secret|token|api_?key|apikey|private_?key|credential)\w*\b`)

// requestLineRE is a line that makes an HTTP request through a client networkActionRE does not name:
// requests' other verbs, httpx, aiohttp, a session or client object's verbs, got/ky/superagent/needle,
// XMLHttpRequest, a WebSocket. CredentialSentElsewhere counts only request lines as destinations
// (P-117): a URL literal anywhere else — an XML namespace, a licence header, an OAuth scope, a
// message string, a test fixture — is not where a credential goes. Measured on the 76 high
// credential-read votes on corpus servers: 38 more benign votes lowered, and the 4 malicious ones
// the old reading also held were all votes describing the server's own key, held by the same
// mistake. The list only widens what counts as a send; a client it misses makes the file read as
// sending nothing, so add to it rather than remove from it.
var requestLineRE = regexp.MustCompile(`(?i)\b(?:requests|httpx|aiohttp|session|client|http_client|httpclient|got|ky|superagent|needle)\s*\.\s*(?:get|post|put|patch|delete|head|request|send|stream)\s*\(` +
	`|\.(?:post|put|patch)\s*\(|\bXMLHttpRequest\b|\bnew\s+WebSocket\s*\(|\bwebsocket\.(?:create_connection|connect)\s*\(|\burlopen\s*\(|\bhttp\.client\b|\bHTTPS?Connection\s*\(`)

// CredentialSentElsewhere reports whether a file reads a credential and sends to a destination it
// spells out that is not that credential's service — the theft shape EXFIL-001's destination check
// keeps high (P-061). A credential is the chain's credential leg or a credNameRE name anywhere in the
// file. A credential with no service in its name (`settings.password`) has no
// service to match, so any spelled-out off-box host counts as elsewhere. A destination built at run
// time is not elsewhere here: unreadable is P-074's ground, and P-098 does not reopen it.
func CredentialSentElsewhere(path, text string) bool {
	c := replay(elsewhereChain(text), path, text)
	if !(c.cred || credNameRE.MatchString(text)) || !c.net {
		return false
	}
	for _, h := range c.destHosts {
		if !hostMatchesService(h, c.credService) {
			return true
		}
	}
	return false
}

// FileText is one file of an artifact, by its path relative to the artifact root.
type FileText struct{ Path, Text string }

// CredentialGoesHomeAcross is CredentialGoesHome over a whole artifact: the credentials named
// anywhere in it against the destinations named anywhere in it. A server reads its key in
// config.py and spends it in client.py, so the per-file answer is false for both files while the
// server as a whole plainly talks only to its own service. The aggregate keeps every guard of the
// per-file chain: one unreadable destination in any file, one destination that matches no named
// credential, or no named credential at all, and the answer is false.
func CredentialGoesHomeAcross(files []FileText) bool {
	services := map[string]bool{}
	var hosts []string
	cred, net, offBox, unreadable := false, false, false, false
	for _, f := range files {
		c := replay(homeChain(f.Text), f.Path, f.Text)
		cred, net = cred || c.cred, net || c.net
		offBox, unreadable = offBox || c.netOffBox, unreadable || c.destUnreadable
		for k := range c.credService {
			services[k] = true
		}
		hosts = append(hosts, c.destHosts...)
	}
	if !cred || !net || len(services) == 0 || unreadable {
		return false
	}
	if !offBox {
		return true
	}
	if len(hosts) == 0 {
		return false
	}
	for _, h := range hosts {
		if !hostMatchesService(h, services) {
			return false
		}
	}
	return true
}
