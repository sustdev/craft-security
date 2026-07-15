<?php

declare(strict_types=1);

namespace sustdev\security\Csp;

use InvalidArgumentException;

/**
 * Catalogue of Content-Security-Policy host sets, one per public third-party
 * service. Adding a service to a policy means adding its whole set to the right
 * directives at once, instead of hand-picking hosts per project.
 *
 * Only generic, publicly documented services live here. Anything project or
 * customer specific (self-hosted analytics hosts, CDN/asset origins, sibling
 * domains, Sentry DSN keys, GTM container hashes, a site's own frame-ancestors,
 * broad Google static wildcards) is passed in by the project through
 * CspBuilder::add()/scriptHash(), never hardcoded here.
 *
 * Each set maps a directive name to a list of host tokens. A service that needs
 * a keyword such as 'unsafe-inline' contributes it as a token like any host.
 *
 * A few services are hosted per deployment (a self-hosted analytics instance, an
 * account-scoped SaaS subdomain). Those take a 'host' option; some have a public
 * default, others require the host.
 */
final class ServiceSets
{
    /** Host-based services with a public default host. */
    private const HOST_DEFAULTS = [
        'plausible' => 'plausible.io',
    ];

    /**
     * Resolve a single service set, applying any options.
     *
     * @param array{host?: string} $options
     * @return array<string, list<string>> directive => host tokens
     */
    public static function get(string $service, array $options = []): array
    {
        $hostBased = self::hostBased();
        if (isset($hostBased[$service])) {
            return ($hostBased[$service])(self::resolveHost($service, $options));
        }

        $catalogue = self::staticCatalogue();
        if (!isset($catalogue[$service])) {
            throw new InvalidArgumentException(sprintf(
                'Unknown CSP service "%s". Known services: %s.',
                $service,
                implode(', ', self::names()),
            ));
        }

        return $catalogue[$service];
    }

    /**
     * @return list<string>
     */
    public static function names(): array
    {
        return array_merge(
            array_keys(self::staticCatalogue()),
            array_keys(self::hostBased()),
        );
    }

    /**
     * Services whose hosts are fixed public infrastructure.
     *
     * @return array<string, array<string, list<string>>>
     */
    private static function staticCatalogue(): array
    {
        return [
            // Sentry browser SDK error/feedback ingest. The wildcards cover a
            // project's own oNNN.ingest.<region>.sentry.io DSN host.
            'sentry-sdk' => [
                'connect-src' => ['*.ingest.de.sentry.io', '*.ingest.us.sentry.io'],
            ],

            'google-tag-manager' => [
                'script-src' => ['*.googletagmanager.com', 'tagmanager.google.com'],
                'style-src' => ['*.googletagmanager.com'],
                'img-src' => ['*.googletagmanager.com'],
                'connect-src' => ['*.googletagmanager.com', 'tagmanager.google.com'],
                'frame-src' => ['www.googletagmanager.com'],
            ],

            // GA4. The bare analytics.google.com apex is needed for /g/collect
            // when Google Signals is on; the wildcard does not match the apex.
            'google-analytics' => [
                'script-src' => ['*.google-analytics.com', '*.analytics.google.com'],
                'img-src' => ['*.google-analytics.com', '*.analytics.google.com'],
                'connect-src' => ['*.google-analytics.com', '*.analytics.google.com', 'analytics.google.com'],
            ],

            // Google Ads / AdSense / DoubleClick. Conversion and remarketing
            // pixels go to the visitor's local google.<tld>, so the full TLD
            // list is spread into img-src and connect-src.
            'google-ads' => [
                'script-src' => ['*.googlesyndication.com', '*.googleadservices.com', '*.doubleclick.net'],
                'img-src' => array_merge(
                    ['*.googlesyndication.com', '*.googleadservices.com', '*.doubleclick.net'],
                    GoogleTlds::list(),
                ),
                'connect-src' => array_merge(
                    ['*.googlesyndication.com', '*.googleadservices.com', '*.doubleclick.net', 'adservice.google.com'],
                    GoogleTlds::list(),
                ),
                'frame-src' => ['*.doubleclick.net'],
            ],

            // Google Maps JavaScript API and its tile / Street View hosts. The
            // Maps API injects inline styles at runtime; on a statically cached
            // site that forces style-src 'unsafe-inline' (a nonce cannot be used
            // with full-page caching).
            'google-maps' => [
                'script-src' => ['maps.googleapis.com'],
                'style-src' => ["'unsafe-inline'"],
                // Enumerate the specific Maps hosts. A broad '*.googleapis.com'
                // is deliberately avoided: it also covers storage.googleapis.com
                // (multi-tenant GCS buckets), a known CSP-allowlist bypass. If
                // Maps needs another exact googleapis subdomain, report-only will
                // surface it and it gets added here specifically.
                'img-src' => [
                    'maps.googleapis.com',
                    'maps.gstatic.com',
                    'khms0.googleapis.com',
                    'khms1.googleapis.com',
                    'streetviewpixels-pa.googleapis.com',
                    '*.ggpht.com',
                ],
                'connect-src' => ['maps.googleapis.com'],
                'frame-src' => ['www.google.com'],
            ],

            'recaptcha' => [
                'script-src' => ['www.google.com', 'www.gstatic.com', 'www.recaptcha.net'],
                'frame-src' => ['www.google.com', 'recaptcha.google.com'],
            ],

            'turnstile' => [
                'script-src' => ['challenges.cloudflare.com'],
                'connect-src' => ['challenges.cloudflare.com'],
                'frame-src' => ['challenges.cloudflare.com'],
            ],

            'meta-pixel' => [
                'script-src' => ['connect.facebook.net'],
                'img-src' => ['*.facebook.com', 'connect.facebook.net'],
                'connect-src' => ['*.facebook.com', 'connect.facebook.net'],
                'frame-src' => ['www.facebook.com'],
            ],

            'microsoft-clarity' => [
                'script-src' => ['*.clarity.ms'],
                'img-src' => ['*.clarity.ms', 'c.bing.com'],
                'connect-src' => ['*.clarity.ms', 'c.bing.com'],
            ],

            'bing-ads' => [
                'script-src' => ['bat.bing.com'],
                'img-src' => ['bat.bing.com', 'c.bing.com'],
                'connect-src' => ['bat.bing.com', 'c.bing.com'],
            ],

            'linkedin-insight' => [
                'script-src' => ['snap.licdn.com'],
                'img-src' => ['px.ads.linkedin.com', '*.ads.linkedin.com', '*.linkedin.com'],
                'connect-src' => ['*.ads.linkedin.com', '*.linkedin.com'],
            ],

            'cookiebot' => [
                'script-src' => ['*.cookiebot.com'],
                'img-src' => ['*.cookiebot.com'],
                'connect-src' => ['*.cookiebot.com'],
                'frame-src' => ['consentcdn.cookiebot.com'],
            ],

            'mouseflow' => [
                'script-src' => ['cdn.mouseflow.com', '*.mouseflow.com'],
                'connect-src' => ['*.mouseflow.com'],
            ],

            'trustpilot' => [
                'script-src' => ['widget.trustpilot.com', '*.trustpilot.com'],
                'img-src' => ['*.trustpilot.com'],
                'connect-src' => ['*.trustpilot.com'],
                'frame-src' => ['widget.trustpilot.com', '*.trustpilot.com'],
            ],

            // Font Awesome and other libraries served from cdnjs. Kept out of
            // script-src by default; a project that loads a script from cdnjs
            // adds it explicitly.
            'cdnjs' => [
                'style-src' => ['cdnjs.cloudflare.com'],
                'font-src' => ['cdnjs.cloudflare.com'],
            ],

            // jsDelivr CDN (scripts, styles, fonts, source maps).
            'jsdelivr' => [
                'script-src' => ['cdn.jsdelivr.net'],
                'style-src' => ['cdn.jsdelivr.net'],
                'font-src' => ['cdn.jsdelivr.net'],
                'connect-src' => ['cdn.jsdelivr.net'],
            ],

            // jQuery CDN.
            'jquery' => [
                'script-src' => ['code.jquery.com'],
            ],

            // Full YouTube video embed: the iframe API script (www.youtube.com
            // redirects to s.ytimg.com), the player iframe (privacy-enhanced
            // nocookie host), the poster thumbnails (ytimg), and the video
            // streams (googlevideo) over connect-src + media-src.
            'youtube' => [
                'script-src' => ['www.youtube.com', 's.ytimg.com'],
                'img-src' => ['*.ytimg.com'],
                'connect-src' => ['*.googlevideo.com', 'www.youtube.com'],
                'media-src' => ["'self'", 'blob:', '*.googlevideo.com'],
                'frame-src' => ['*.youtube.com', 'www.youtube-nocookie.com'],
            ],

            // Gravatar avatar images.
            'gravatar' => [
                'img-src' => ['*.gravatar.com'],
            ],

            // Google-hosted user content (avatars, uploaded images).
            'google-user-content' => [
                'img-src' => ['*.googleusercontent.com'],
            ],

            // Google Apps Script webhooks. The exec URL on script.google.com
            // redirects to script.googleusercontent.com.
            'google-apps-script' => [
                'connect-src' => ['script.google.com', 'script.googleusercontent.com'],
            ],

            // ipify public IP-address lookup.
            'ipify' => [
                'connect-src' => ['api.ipify.org', 'api64.ipify.org'],
            ],
        ];
    }

    /**
     * Services hosted per deployment: the set is a closure of the resolved host.
     *
     * @return array<string, callable(string): array<string, list<string>>>
     */
    private static function hostBased(): array
    {
        return [
            // Plausible analytics. Defaults to the public SaaS host; a
            // self-hosted instance passes its own host.
            'plausible' => static fn (string $host): array => [
                'script-src' => [$host],
                'connect-src' => [$host],
            ],

            // ActiveCampaign forms/tracking on the account subdomain
            // (<account>.activehosted.com). No public default; host required.
            'active-campaign' => static fn (string $host): array => [
                'script-src' => [$host],
                'connect-src' => [$host],
            ],
        ];
    }

    /**
     * @param array{host?: string} $options
     */
    private static function resolveHost(string $service, array $options): string
    {
        if (isset($options['host']) && $options['host'] !== '') {
            return $options['host'];
        }

        if (isset(self::HOST_DEFAULTS[$service])) {
            return self::HOST_DEFAULTS[$service];
        }

        throw new InvalidArgumentException(sprintf(
            'CSP service "%s" requires a host, e.g. use(\'%s\', [\'host\' => \'...\']).',
            $service,
            $service,
        ));
    }
}
