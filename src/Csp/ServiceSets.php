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
 * customer specific (self-hosted analytics hosts, CDN origins, sibling domains,
 * Sentry DSN keys, GTM container hashes, one-off integrations) is passed in by
 * the project through CspBuilder::add()/scriptHash(), never hardcoded here.
 *
 * Each set maps a directive name to a list of host tokens. A service that needs
 * a keyword such as 'unsafe-inline' contributes it as a token like any host.
 */
final class ServiceSets
{
    /**
     * Services whose host depends on the deployment (e.g. a self-hosted
     * instance). The default is the public SaaS host; a project overrides it
     * with the 'host' option.
     */
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
        $catalogue = self::catalogue($options);

        if (!isset($catalogue[$service])) {
            throw new InvalidArgumentException(sprintf(
                'Unknown CSP service "%s". Known services: %s.',
                $service,
                implode(', ', array_keys($catalogue)),
            ));
        }

        return $catalogue[$service];
    }

    /**
     * @return list<string>
     */
    public static function names(): array
    {
        return array_keys(self::catalogue());
    }

    /**
     * @param array{host?: string} $options
     * @return array<string, array<string, list<string>>>
     */
    private static function catalogue(array $options = []): array
    {
        return [
            // Sentry browser SDK error/feedback ingest. The ingest hosts are
            // generic Sentry infrastructure; the wildcards cover a project's own
            // oNNN.ingest.<region>.sentry.io DSN host.
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
                'img-src' => [
                    'maps.googleapis.com',
                    'maps.gstatic.com',
                    'khms0.googleapis.com',
                    'khms1.googleapis.com',
                    'streetviewpixels-pa.googleapis.com',
                    '*.ggpht.com',
                    '*.googleapis.com',
                ],
                'connect-src' => ['maps.googleapis.com', '*.googleapis.com'],
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
                'img-src' => ['px.ads.linkedin.com', '*.ads.linkedin.com'],
                'connect-src' => ['*.ads.linkedin.com'],
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

            'youtube' => [
                'img-src' => ['*.ytimg.com'],
                'frame-src' => ['*.youtube.com', 'www.youtube-nocookie.com'],
            ],

            // Plausible analytics. Defaults to the public SaaS host; a
            // self-hosted instance passes its own host via the 'host' option.
            'plausible' => [
                'script-src' => [self::host('plausible', $options)],
                'connect-src' => [self::host('plausible', $options)],
            ],
        ];
    }

    /**
     * @param array{host?: string} $options
     */
    private static function host(string $service, array $options): string
    {
        return $options['host'] ?? self::HOST_DEFAULTS[$service];
    }
}
