// patterns.go
package main

var RegexPatterns = map[string]string{
	// --- API Keys / Cloud ---
	"Google API Key":                      `AIza[0-9A-Za-z\-_]{35}`,
	"Google OAuth Access Token":           `ya29\.[0-9A-Za-z\-_]+`,
	"Firebase API Key":                    `AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}`,
	"AWS Access Key ID":                   `A[SK]IA[0-9A-Z]{16}`,
	"AWS Secret Access Key (env/var)":	   `(?i)(?:aws[_\- ]?secret[_\- ]?access[_\- ]?key|aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"]?([A-Za-z0-9+/]{40})['"]?`,
	"DigitalOcean Token":                  `dop_v1_[a-f0-9]{64}`,
	"Heroku API Key":                      `heroku_[0-9a-fA-F]{32}`,
	"GitHub Token":                        `ghp_[A-Za-z0-9]{36,}`,
	"GitLab Token":                        `glpat-[0-9a-zA-Z\-_]{20,}`,
	"Slack Webhook":                       `https://hooks.slack.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+`,
	"Slack Token":                         `xox[baprs]-[0-9a-zA-Z]{10,48}`,
	"Stripe Live Key":                     `sk_live_[0-9a-zA-Z]{24}`,
	"SendGrid API Key":                    `SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`,
	"Mailgun API Key":                     `key-[0-9a-zA-Z]{32}`,
	"Facebook Access Token":               `EAACEdEose0cBA[0-9A-Za-z]+`,
	"Telegram Bot Token":                  `\d{9}:[a-zA-Z0-9_-]{35}`,
	"Discord Token":                       `[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}`,
	"X API Key":                           `"X-API-KEY":"([0-9a-fA-F-]+)"`,
	"AccessKey":		       			   `accesskey:\s*"[^"]*`,
	"SecretKey":		       			   `secretkey:\s*"[^"]*`,
	"Vue App Api Server Url":			   `"VUE_APP_API_SERVER_URL_XDLP":\s*"[^"]*"`,
	"Vue App Publishable Key":			   `"VUE_APP_CHARGEBEE_PUBLISHABLE_KEY":\s*"[^"]*"`,
	"Vue App Auth Client Id":			   `"VUE_APP_GAPI_AUTH_CLIENT_ID":\s*"[^"]*"`,
	"Vue App Teams Client Id":			   `"VUE_APP_GENCORE_MS_TEAMS_CLIENT_ID":\s*"[^"]*"`,
    "Authorization_basic":				   `Basic\s+[a-zA-Z0-9\+\/=]{24}`,
    "Authorization_bearer":				   `Bearer\s+[a-zA-Z0-9\-_\.]{24}(\.[a-zA-Z0-9\-_\.]{44}){2}`,
    "Authorization_api":				   `api_key\s+[A-Z0-9]{5}(\-[A-Z0-9]{5}){4}`,
	"Configuration API Key":			   `"CONFIGURATION_API_KEY":"[A-Za-z0-9]+"`,

	// --- Auth / JWT / Session ---
	"JWT Token":                           `eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`,
	"Bearer Token":                        `(?i)bearer\s+[A-Za-z0-9_\-\.=:_\+\/]+`,
	"Basic Auth Header":                   `(?i)basic\s+[A-Za-z0-9=:_\+\/-]{5,100}`,
	"Session ID":                          `(sessionid|_session|sessid|connect\.sid|sid|JSESSIONID|PHPSESSID)=[A-Za-z0-9\-_]{10,}`,
	"CSRF Token":                          `(?i)csrf(_token|middlewaretoken|token)?[=:]['"]?[A-Za-z0-9\-_]{8,}`,

	// --- Database URIs ---
	"MongoDB URI":                         `mongodb(?:\+srv)?:\/\/(?:[A-Za-z0-9._%+\-]+:[^@]+@)?[A-Za-z0-9\.\-]+(?::\d+)?\/[A-Za-z0-9._%+\-]+`,
	"PostgreSQL URI":                      `postgres(?:ql)?:\/\/(?:[A-Za-z0-9._%+\-]+:[^@]+@)?[A-Za-z0-9\.\-]+(?::\d+)?\/[A-Za-z0-9._%+\-]+`,
	"MySQL URI":                           `mysql:\/\/(?:[A-Za-z0-9._%+\-]+:[^@]+@)?[A-Za-z0-9\.\-]+(?::\d+)?\/[A-Za-z0-9._%+\-]+`,
	"Redis URI":                           `redis:\/\/(?:[A-Za-z0-9._%+\-]+:[^@]+@)?[A-Za-z0-9\.\-]+(?::\d+)?`,

	// --- Private Keys ---
	"RSA PRIVATE KEY":                     `-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----`,
	"OPENSSH PRIVATE KEY":                 `-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----`,
	"PGP PRIVATE KEY BLOCK":               `-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----`,

	// --- Cloud Buckets / Endpoints ---
	"S3 Bucket URL":                       `[A-Za-z0-9\-_]+\.s3(?:[.-][A-Za-z0-9\-_]+)?\.amazonaws\.com|s3:\/\/[A-Za-z0-9\-_]+`,
	"Firebase DB URL":                     `https?:\/\/[a-z0-9\-]+\.firebaseio\.com`,

	// --- Config / Secrets / Env Vars ---
	"ENV Style Secrets":                   `(?i)(?:api[_\- ]?key|access[_\- ]?token|client[_\- ]?secret|secret|refresh[_\- ]?token)[=:]['"]?([A-Za-z0-9\-_\/+=\.]{8,})['"]?`,
	"Password Variable":                   `(?i)(?:password|passwd|pwd|passphrase)[\s]*[:=][\s]*['"]?([^\s'"]{4,})['"]?`,

	// --- Miscellaneous ---
	"Email Address":                       `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,7}`,
	"UUID":                                `\b[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}\b`,
	"IPv4":                                `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
}
