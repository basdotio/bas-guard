// SPDX-License-Identifier: MIT
package detect

// The domains a well-known service's name is really registered under (P-145).
//
// hostMatchesService lets a host vouch for a credential when the host's registrable label is the
// credential's service token: `STRIPE_SECRET_KEY` and `api.stripe.com`. The label says nothing
// about the suffix after it, so `stripe.xyz`, which anyone may register, vouched as well as
// `stripe.com`. Telling the two apart takes a fact no host name carries: which suffix the service
// uses. This table is that fact, for the services whose keys are worth stealing.
//
// What it does, and all it does: for a token listed here, a host vouches only when its registrable
// DOMAIN is one of the token's. It is a narrowing. Every domain below has the token as its
// registrable label, so no entry makes a host vouch that did not vouch before (the test
// TestServiceDomains_OnlyNarrow holds the table to that); a token that is not listed is matched as
// it always was, by its label under any suffix. An empty entry means no host named after the token
// is the service's own: AWS's API lives under amazonaws.com and npm's registry under npmjs.org, so
// a host called `aws.<anything>` or `npm.<anything>` is somebody else's.
//
// What belongs here: a service whose credential an attacker would send to a look-alike — a cloud,
// a code host, a model or search API, a payment or exchange account, a messaging or workspace
// account — and whose domains are known beyond doubt. A domain that is not certainly the service's
// own must not be added: a missing domain costs a false alarm on one real client, a wrong one is a
// host that vouches for a key it has no claim to. The long tail of small services stays outside,
// on purpose: of the 54 services whose host vouched for their key in the corpus and the fresh
// skills on 2026-11-20, most appear once and use whatever suffix they found (`.ai`, `.io`, `.dev`,
// `.tech`, `.to`, even `.xyz`), so a rule about suffixes in general would flag them all.
//
// A domain is written whole. Where the service lives under a country's second level the entry
// carries all three labels.
var serviceDomains = map[string][]string{
	// Clouds and platforms.
	"aws":          {}, // amazonaws.com, a hosted suffix: no host named aws is its API
	"amazon":       {"amazon.com"},
	"gcp":          {}, // googleapis.com
	"google":       {"google.com"},
	"azure":        {"azure.com"},
	"microsoft":    {"microsoft.com"},
	"cloudflare":   {"cloudflare.com"},
	"digitalocean": {"digitalocean.com"},
	"heroku":       {"heroku.com"},
	"vercel":       {"vercel.com"},
	"netlify":      {"netlify.com"},
	"supabase":     {"supabase.co", "supabase.com"},
	"mongodb":      {"mongodb.com", "mongodb.net"},
	"pinecone":     {"pinecone.io"},

	// Code hosts, registries, developer tools.
	"github":    {"github.com"},
	"gitlab":    {"gitlab.com"},
	"bitbucket": {"bitbucket.org"},
	"npm":       {}, // npmjs.org, npmjs.com
	"pypi":      {"pypi.org"},
	"docker":    {"docker.com", "docker.io"},
	"sentry":    {"sentry.io"},
	"datadog":   {}, // datadoghq.com, datadoghq.eu
	"linear":    {"linear.app"},
	"notion":    {"notion.com", "notion.so"},
	"figma":     {"figma.com"},
	"atlassian": {"atlassian.com", "atlassian.net"},
	"jira":      {}, // atlassian.net
	"airtable":  {"airtable.com"},
	"asana":     {"asana.com"},
	"trello":    {"trello.com"},
	"clickup":   {"clickup.com"},

	// Model, speech and search APIs.
	"openai":      {"openai.com"},
	"anthropic":   {"anthropic.com"},
	"claude":      {"claude.ai", "claude.com"},
	"mistral":     {"mistral.ai"},
	"groq":        {"groq.com"},
	"cohere":      {"cohere.com", "cohere.ai"},
	"replicate":   {"replicate.com"},
	"perplexity":  {"perplexity.ai"},
	"deepseek":    {"deepseek.com"},
	"openrouter":  {"openrouter.ai"},
	"huggingface": {"huggingface.co"},
	"together":    {"together.xyz", "together.ai"},
	"fireworks":   {"fireworks.ai"},
	"xai":         {}, // x.ai
	"elevenlabs":  {"elevenlabs.io"},
	"tavily":      {"tavily.com"},
	"serper":      {"serper.dev"},
	"serpapi":     {"serpapi.com"},
	"brave":       {"brave.com"},
	"jina":        {"jina.ai"},
	"exa":         {"exa.ai"},
	"firecrawl":   {"firecrawl.dev"},

	// Messaging, mail and social accounts.
	"slack":     {"slack.com"},
	"discord":   {"discord.com"},
	"telegram":  {"telegram.org"},
	"twilio":    {"twilio.com"},
	"sendgrid":  {"sendgrid.com", "sendgrid.net"},
	"mailgun":   {"mailgun.net", "mailgun.com"},
	"resend":    {"resend.com"},
	"zoom":      {"zoom.us", "zoom.com"},
	"intercom":  {"intercom.io", "intercom.com"},
	"zendesk":   {"zendesk.com"},
	"hubspot":   {"hubspot.com"},
	"linkedin":  {"linkedin.com"},
	"twitter":   {"twitter.com"},
	"reddit":    {"reddit.com"},
	"facebook":  {"facebook.com"},
	"instagram": {"instagram.com"},
	"whatsapp":  {"whatsapp.com"},
	"spotify":   {"spotify.com"},
	"dropbox":   {"dropbox.com"},

	// Payments, shops and exchanges.
	"stripe":   {"stripe.com"},
	"paypal":   {"paypal.com"},
	"shopify":  {"shopify.com"},
	"binance":  {"binance.com", "binance.us"},
	"coinbase": {"coinbase.com"},
}
