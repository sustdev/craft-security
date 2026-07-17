# Sustdev Security

Server-side security hardening for Craft CMS 5.

## Version 1: password complexity

Enforces configurable complexity on new passwords, server-side only. Nothing is
rendered on the front end. The rules apply to the `newPassword` attribute, so
they run when a password is set (registration, change, admin or
forgot-password reset). Login authenticates against the stored hash and never
runs them, so raising the policy does not lock out existing accounts; the
stricter rules apply the next time each user sets a password.

## Configuration

Everything is driven by a config file, there are no control-panel settings.
Copy `src/config.php` to `config/security.php` and set only what differs from
the defaults:

```php
return [
    'passwordMinLength' => 12,
];
```

Available keys: `passwordComplexity`, `passwordMinLength`, `passwordMaxLength`,
`passwordRequireLowercase`, `passwordRequireUppercase`, `passwordRequireNumber`,
`passwordRequireSymbol`, `passwordMessage`. See `src/config.php` for the
defaults and what each does.

Messages are translatable (English source, Dutch included); override the
complexity message per site with `passwordMessage`.

### Exposing the policy to a client

Enforcement is server-side, but a form usually validates the password in the
browser too for instant feedback. To keep that in sync with the server (one
source of truth), read the policy from the plugin instead of hardcoding it, and
render it into the page for your client validator to consume:

```php
$policy = \sustdev\security\Plugin::getInstance()->getPasswordPolicy();
// Shape: ['enabled' => bool, 'minLength' => int, 'maxLength' => int,
//  'requireLowercase' => bool, 'requireUppercase' => bool,
//  'requireNumber' => bool, 'requireSymbol' => bool]
// The four require* flags follow config/security.php (all true by default;
// the example below reflects a min-length-only tuning). When complexity is
// disabled, `enabled` is false and the policy reports no constraints
// (minLength 0, no max), so a client mirror never out-validates the server.

$hint = \sustdev\security\Plugin::getInstance()->getPasswordRequirementsText();
// e.g. "at least 8 characters" for a min-length-only policy, or
// "at least 12 characters, a number, a special character" with classes on.
// Empty when complexity is disabled.
```

The policy is derived from the same settings as the validation rules, so raising
`config/security.php` updates the server, the client mirror and the hint at
once. The package still renders nothing itself; the project decides how to
surface the data (e.g. a `type="application/json"` block the form reads).

## Content-Security-Policy building blocks

A CSP is a shared base plus a set of hosts per third-party service you run. The
`Csp\CspBuilder` composes a policy from named service sets, so a project declares
*which services it uses* instead of hand-maintaining host lists (and drifting out
of sync with other projects). It pairs with the Sherlock plugin, whose
`contentSecurityPolicySettings.directives` takes the array `directives()` returns.

Only generic, publicly documented services live in the catalogue. Anything
project or customer specific (self-hosted analytics hosts, CDN origins, sibling
domains, Sentry DSN keys, GTM container hashes, one-off integrations) is passed in
per project with `add()` / `scriptHash()`, never baked into this package.

### Inline event handler attributes

A strict `script-src` blocks inline handlers (`onload=`, `onclick=`). To keep one
specific handler working, register its hash with `scriptAttrHash()`. That emits a
`script-src-attr` directive holding `'unsafe-hashes'` plus the hash, which governs
handler attributes *only*, so the `scriptHash()` entries on `script-src` stay
ineligible as handler bodies. Without a `scriptAttrHash()` call the directive is
never emitted and handlers keep falling back to `script-src`.

Hash the attribute value verbatim:

```
printf "%s" "this.media='all'" | openssl dgst -sha256 -binary | openssl base64
```

Hash a snippet the project itself renders, not one a plugin emits: a plugin
upgrade can change its own bytes and break the hash silently. Where a plugin lets
you supply the attribute (Vite's `craft.vite.script()` takes `$cssTagAttrs`), pass
your own and hash that.

### Usage (config/sherlock.php)

```php
use craft\helpers\App;
use sustdev\security\Csp\CspBuilder;

$isDev = App::env('CRAFT_ENVIRONMENT') === 'dev';
$isProduction = App::env('CRAFT_ENVIRONMENT') === 'production';

$csp = CspBuilder::make($isDev)
    ->reportUri('https://oNNN.ingest.de.sentry.io/api/NNN/security/?sentry_key=...')
    ->use('google-tag-manager')
    ->use('google-analytics')
    ->use('google-ads')          // includes the full Google TLD list in img-src + connect-src
    ->use('google-maps')
    ->use('cookiebot')
    ->use('plausible', ['host' => 'privacy.example.com']) // self-hosted instance
    ->add('img-src', $cloudFrontOrigin)                    // project-specific host
    ->scriptHash("'sha256-...'")                           // inline GTM bootstrap, prod only
    ->scriptAttrHash("'sha256-...'")                       // inline onload= handler, prod only
    ->viteDevServer($isDev ? App::env('PRIMARY_SITE_URL') . ':3000' : '');

return [
    '*' => [
        'contentSecurityPolicySettings' => [
            // Posture stays with the project: it differs per environment.
            'enabled' => $isProduction || $isDev,
            'enforce' => $isDev,
            'header' => true,
            'directives' => $csp->directives(),
        ],
    ],
];
```

### Available services

`sentry-sdk`, `google-tag-manager`, `google-analytics`, `google-ads`,
`google-maps`, `google-maps-embed`, `recaptcha`, `turnstile`, `mailerlite`,
`meta-pixel`,
`microsoft-clarity`, `bing-ads`, `linkedin-insight`, `cookiebot`, `mouseflow`,
`trustpilot`, `cdnjs`, `jsdelivr`, `jquery`, `youtube`, `gravatar`,
`google-user-content`, `google-apps-script`, `ipify`, `algolia`, `mapbox`,
`plausible`, `active-campaign`, `matomo`.

`google-maps` is the Maps JavaScript API; `google-maps-embed` is the classic
iframe embed, which only needs `frame-src`.

Each set adds its hosts to the correct directives (`ServiceSets` is the source of
truth). An unknown service name throws, so a typo fails loudly.

Three services are hosted per deployment and take a `['host' => ...]` option:
`plausible` (defaults to the public `plausible.io`; pass the host for a
self-hosted instance), `active-campaign` (the account subdomain
`<account>.activehosted.com`; no default, so the host is required) and `matomo`
(a self-hosted instance or an account-scoped `<account>.matomo.cloud` subdomain;
no default, so the host is required).

### Design notes

- `google-ads` carries Google's full published `supported_domains` list, because
  Ads conversion and remarketing pixels are sent to the visitor's own-country
  `google.<tld>` and CSP allows no wildcard to the right of the host.
- `google-analytics` includes the bare `analytics.google.com` apex, which
  `/g/collect` uses when Google Signals is on and the wildcard cannot match.
- Inline hashes and `'unsafe-inline'` are mutually exclusive in `script-src`, so
  the builder uses the hash in production and `'unsafe-inline'` in dev.
- Hosts are deduplicated per directive.

Run the tests with `composer test`.
