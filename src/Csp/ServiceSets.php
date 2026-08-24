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
                // The Maps JS API injects a <link> to fonts.googleapis.com for its
                // UI type (Roboto / Google Sans) and pulls the font files from
                // fonts.gstatic.com. These are the Maps runtime's own fonts, not
                // the site's, so they can't be self-hosted.
                'style-src' => ["'unsafe-inline'", 'fonts.googleapis.com'],
                'font-src' => ['fonts.gstatic.com'],
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

            // Google Places API, the newer places.googleapis.com v1 endpoint (not
            // the classic maps/api/place, which lives under maps.googleapis.com and
            // is already covered by google-maps). Its own set rather than folded
            // into google-maps because Places is a separate service: a form's
            // address autocomplete uses it with no map on the page. The Maps JS
            // library also calls it once a site enables its Places features, but a
            // site can use it on its own too, so declare it where it is used.
            //  - connect-src: the RPC lookups (place details, autocomplete). This
            //    is what was measured blocked. Place-photo hosts on img-src are
            //    left out until a real embed reports one, the same
            //    enumerate-what-is-seen approach as google-maps above.
            'google-places' => [
                'connect-src' => ['places.googleapis.com'],
            ],

            // The other Maps variant: the classic iframe embed, whose src looks
            // like maps.google.com/maps?...&output=embed. Everything the map pulls
            // is requested by Google's own document inside the iframe, which ships
            // its own CSP, so frame-src is all the embedding page needs. Use this
            // instead of 'google-maps' unless the project loads the Maps
            // JavaScript API itself: that set grants six hosts a plain embed never
            // requests.
            //
            // Both hosts are required. The iframe src names maps.google.com, which
            // redirects to www.google.com/maps/embed, and frame-src is matched
            // against the frame's origin after the redirect.
            'google-maps-embed' => [
                'frame-src' => ['maps.google.com', 'www.google.com'],
            ],

            'recaptcha' => [
                'script-src' => ['www.google.com', 'www.gstatic.com', 'www.recaptcha.net'],
                // reCAPTCHA verifies the token via an XHR to www.google.com.
                'connect-src' => ['www.google.com'],
                'frame-src' => ['www.google.com', 'recaptcha.google.com'],
            ],

            'turnstile' => [
                'script-src' => ['challenges.cloudflare.com'],
                'connect-src' => ['challenges.cloudflare.com'],
                'frame-src' => ['challenges.cloudflare.com'],
            ],

            // MailerLite embedded signup form: its scripts and jQuery/inputmask
            // (mlcdn), stylesheets, webfonts and form submit. Pair with the
            // recaptcha set, which MailerLite forms use for spam protection.
            'mailerlite' => [
                'script-src' => ['*.mailerlite.com', '*.mlcdn.com'],
                'style-src' => ['*.mailerlite.com', '*.mlcdn.com'],
                'font-src' => ['*.mailerlite.com'],
                'connect-src' => ['*.mailerlite.com'],
            ],

            'meta-pixel' => [
                'script-src' => ['connect.facebook.net'],
                'img-src' => ['*.facebook.com', 'connect.facebook.net'],
                'connect-src' => ['*.facebook.com', 'connect.facebook.net'],
                'frame-src' => ['www.facebook.com'],
                // For larger event payloads the pixel falls back from the image
                // beacon to a hidden <form> that posts to www.facebook.com/tr
                // (targeting a hidden iframe), so form-action needs that host.
                'form-action' => ['www.facebook.com'],
            ],

            'microsoft-clarity' => [
                'script-src' => ['*.clarity.ms'],
                'img-src' => ['*.clarity.ms', 'c.bing.com'],
                'connect-src' => ['*.clarity.ms', 'c.bing.com'],
            ],

            'bing-ads' => [
                // bat.js is served from bat.bing.com, but the UET beacons it
                // fires (actionp/... pageHide, image + fetch) post to
                // bat.bing.net, so that host is needed for img-src/connect-src
                // but not script-src.
                'script-src' => ['bat.bing.com'],
                'img-src' => ['bat.bing.com', 'bat.bing.net', 'c.bing.com'],
                'connect-src' => ['bat.bing.com', 'bat.bing.net', 'c.bing.com'],
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

            // YouTube embed, parent-page scope only. A cross-origin iframe runs
            // in its own browsing context with its own CSP, so the embedding
            // page's policy governs only what that page itself loads:
            //  - frame-src: the player iframe (privacy-enhanced nocookie host),
            //    plus the youtu.be short link. frame-src governs every navigation
            //    of the nested browsing context, not just the initial src, so the
            //    player navigating itself to the short link is checked against it
            //    too. youtu.be is a separate registrable domain, so the
            //    *.youtube.com wildcard does not cover it. Measured from an
            //    enforced frame-src violation reported for youtu.be on a page
            //    whose only embed was a plain youtube.com/embed iframe; what
            //    triggered that navigation was not captured. The reported URI
            //    carried no path because blocked-uri is stripped to the origin
            //    when the blocked resource is cross-origin.
            //  - img-src: the poster thumbnail the page renders (ytimg).
            //  - script-src: the JS IFrame Player API, if the page loads it
            //    (www.youtube.com/iframe_api pulls the widget from s.ytimg.com).
            // The in-iframe video streams (*.googlevideo.com) load inside the
            // iframe's own context, not the parent, so connect-src/media-src are
            // intentionally not here. A project that measures a real parent-side
            // need (a lazy-load facade lib, an unusual integration) adds them.
            'youtube' => [
                'script-src' => ['www.youtube.com', 's.ytimg.com'],
                'img-src' => ['*.ytimg.com'],
                'frame-src' => ['*.youtube.com', 'www.youtube-nocookie.com', 'youtu.be'],
            ],

            // Vimeo embed, parent-page scope only (same reasoning as youtube
            // above: a cross-origin iframe carries its own CSP):
            //  - frame-src: the player iframe (player.vimeo.com). This is all a
            //    raw <iframe src="//player.vimeo.com/video/..."> embed needs, and
            //    is what was measured on a real embed.
            //  - script-src: the Player SDK, if the page loads it
            //    (player.vimeo.com/api/player.js) to control the iframe from the
            //    parent. Same host as the frame.
            //  - img-src: the poster thumbnail a facade/lazy-load renders on the
            //    page itself (i.vimeocdn.com), if used.
            // The in-iframe assets (f.vimeocdn.com player scripts/css, the video
            // streams) load inside the iframe's own context, not the parent, so
            // they are intentionally not here.
            'vimeo' => [
                'script-src' => ['player.vimeo.com'],
                'img-src' => ['i.vimeocdn.com'],
                'frame-src' => ['player.vimeo.com'],
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

            // Algolia search. The client talks to the app's DSN host and the
            // *.algolianet.com retry hosts over XHR; Insights posts to *.algolia.io.
            // The InstantSearch/autocomplete JS itself is normally bundled, so no
            // script host is included by default (a project loading it from a CDN
            // adds that via jsdelivr/cdnjs or add()).
            'algolia' => [
                'connect-src' => ['*.algolia.net', '*.algolianet.com', '*.algolia.io'],
            ],

            // Mapbox. GL JS fetches tiles, styles, fonts and sprites from
            // api.mapbox.com over XHR (connect-src) and renders them on a canvas,
            // so it needs no image host: the base policy's img-src data:/blob: and
            // worker-src blob: already cover its canvas and blob: workers.
            // events.mapbox.com is GL JS telemetry. api.mapbox.com stays in img-src
            // for the Static Images API, which is loaded as a plain <img>. GL JS on
            // the Standard style or 3D models additionally needs script-src
            // 'wasm-unsafe-eval'; add that per project with ->add() when used.
            'mapbox' => [
                'script-src' => ['api.mapbox.com'],
                'img-src' => ['api.mapbox.com'],
                'connect-src' => ['api.mapbox.com', 'events.mapbox.com'],
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

            // Matomo analytics: a self-hosted instance or an account-scoped Matomo
            // Cloud subdomain (<account>.matomo.cloud). No public default; host
            // required. Loads matomo.js, posts to matomo.php and drops a tracking
            // pixel, so the host goes in script-, connect- and img-src.
            'matomo' => static fn (string $host): array => [
                'script-src' => [$host],
                'img-src' => [$host],
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
