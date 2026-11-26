// SPDX-License-Identifier: MIT
package collect

import (
	"testing"

	"github.com/basdotio/bas-guard/internal/model"
)

// TestHoldsSecret pins the question FS-006 asks of a chmod target (P-152): a file that holds a
// secret and nothing else. It is answered from credentialFile and sensitiveDirs, the two lists
// CredentialPath reads; the rows marked "not here" are paths CredentialPath refuses to import and
// HoldsSecret does not call a secret, each for the reason its comment gives.
func TestHoldsSecret(t *testing.T) {
	for path, want := range map[string]bool{
		// by name, wherever the file sits
		"/root/.netrc":                     true,
		"~/.netrc":                         true,
		"$HOME/.git-credentials":           true,
		".env":                             true,
		"/srv/app/.env.production":         true,
		"/etc/reflow-toolkit/operator.key": true,
		"deploy/keys/signing.p12":          true,
		"id_rsa":                           true,
		// by name, although the path passes through .config
		"/root/.config/powerliftpro/coefficients-api.key": true,
		// inside a credential directory
		"~/.ssh/deploy_key":              true,
		"~/.ssh/aws.pem":                 true, // inside .ssh a .pem is a private key
		"~/.ssh/*":                       true, // every file of .ssh
		"${HOME}/.aws/credentials":       true,
		"~/.aws/config":                  true,
		"~/.gnupg/private-keys-v1.d":     true,
		"~/.kube/config":                 true,
		"/home/dev/.docker/config.json":  true,
		"~/.password-store/work/api.gpg": true,
		// not here: public by design
		"~/.ssh/id_ed25519.pub":  false,
		"~/.ssh/*.pub":           false,
		"~/.ssh/authorized_keys": false,
		"~/.ssh/known_hosts":     false,
		"~/.ssh/config":          false,
		// not here: the directory itself
		"~/.ssh":       false,
		"~/.ssh/":      false,
		"/root/.gnupg": false,
		// not here: the medium tier, and anything merely under .config
		"/etc/ssl/certs/server.pem":   false,
		"~/.npmrc":                    false,
		"~/.pypirc":                   false,
		"~/.config/app/settings.json": false,
		"/root/.config/pip/pip.conf":  false,
		// not here: the file an author ships to show the shape, and ordinary files
		".env.example":   false,
		"config.sample":  false,
		"README.md":      false,
		"scripts/run.sh": false,
		"":               false,
		"/":              false,
	} {
		if got := HoldsSecret(path); got != want {
			t.Errorf("HoldsSecret(%q) = %v, want %v", path, got, want)
		}
	}
}

// TestHoldsSecret_ReadsTheListsCredentialPathReads: every name credentialFile puts in its high tier is
// a secret here, and none of its medium tier is. A name added to one tier moves both answers, so the
// two questions cannot drift into two lists.
func TestHoldsSecret_ReadsTheListsCredentialPathReads(t *testing.T) {
	for _, name := range []string{".env", ".env.local", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "credentials", "credentials.json",
		".git-credentials", "secrets.yml", "secrets.yaml", ".netrc", ".htpasswd", "a.key", "a.p12", "a.pfx", "a.jks", "a.keystore",
		".npmrc", ".pypirc", "a.pem", "notes.txt"} {
		sev, ok := credentialFile(name)
		if want := ok && sev == model.SevHigh; HoldsSecret("/srv/"+name) != want {
			t.Errorf("HoldsSecret(/srv/%s) = %v, but credentialFile says high tier = %v", name, !want, want)
		}
	}
	for dir := range sensitiveDirs {
		if dir == ".netrc" {
			continue // a file name kept on the directory list; the name tier answers for it
		}
		if want := dir != ".config"; HoldsSecret("/home/u/"+dir+"/some-file") != want {
			t.Errorf("HoldsSecret(/home/u/%s/some-file) = %v, want %v", dir, !want, want)
		}
	}
}
