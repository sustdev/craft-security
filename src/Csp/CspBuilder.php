<?php

declare(strict_types=1);

namespace sustdev\security\Csp;

/**
 * Composes a Content-Security-Policy from a shared base plus named service sets.
 *
 * A project declares which public services it runs; the builder merges each
 * service's hosts into the right directives, deduplicates, and returns the
 * directive array in the shape the Sherlock plugin expects.
 *
 * Project specific hosts (CDN origins, self-hosted analytics, sibling domains,
 * one-off integrations) are added with add(); inline script hashes with
 * scriptHash(). Enforcement posture (enabled/enforce) stays with the project,
 * because it differs per environment.
 *
 * Example (config/sherlock.php):
 *
 *   use sustdev\security\Csp\CspBuilder;
 *
 *   $csp = CspBuilder::make($isDev, $isProduction)
 *       ->reportUri($sentryCspReportUri)
 *       ->use('google-tag-manager')
 *       ->use('google-analytics')
 *       ->use('google-ads')
 *       ->use('cookiebot')
 *       ->use('plausible', ['host' => 'privacy.example.com'])
 *       ->add('img-src', $cloudFrontOrigin)
 *       ->scriptHash("'sha256-...'")
 *       ->viteDevServer($viteHost);
 *
 *   return ['*' => ['contentSecurityPolicySettings' => [
 *       'enabled' => $isProduction || $isDev,
 *       'enforce' => $isDev,
 *       'header' => true,
 *       'directives' => $csp->directives(),
 *   ]]];
 */
final class CspBuilder
{
    /**
     * Emission order for the final header. Directives not listed here are
     * dropped; directives listed but empty are skipped.
     *
     * @var list<string>
     */
    private const ORDER = [
        'default-src',
        'script-src',
        'style-src',
        'font-src',
        'img-src',
        'connect-src',
        'media-src',
        'manifest-src',
        'base-uri',
        'object-src',
        'frame-ancestors',
        'frame-src',
        'form-action',
        'worker-src',
    ];

    /** @var array<string, list<string>> directive => tokens */
    private array $directives;

    /** @var list<string> */
    private array $scriptHashes = [];

    private ?string $reportUri = null;

    public function __construct(
        private readonly bool $isDev = false,
        private readonly bool $isProduction = false,
    ) {
        $this->directives = [
            'default-src' => ["'self'"],
            'script-src' => ["'self'"],
            'style-src' => ["'self'"],
            'font-src' => ["'self'", 'data:'],
            'img-src' => ["'self'", 'data:', 'blob:'],
            'connect-src' => ["'self'"],
            'base-uri' => ["'self'"],
            'object-src' => ["'none'"],
            'frame-ancestors' => ["'self'"],
            'form-action' => ["'self'"],
            'worker-src' => ["'self'", 'blob:'],
        ];
    }

    public static function make(bool $isDev = false, bool $isProduction = false): self
    {
        return new self($isDev, $isProduction);
    }

    /**
     * Add a public service set (see ServiceSets) to the policy.
     *
     * @param array{host?: string} $options
     */
    public function use(string $service, array $options = []): self
    {
        foreach (ServiceSets::get($service, $options) as $directive => $hosts) {
            $this->add($directive, ...$hosts);
        }

        return $this;
    }

    /**
     * Add one or more host tokens to a directive (project specific hosts).
     */
    public function add(string $directive, string ...$hosts): self
    {
        $this->directives[$directive] = array_merge(
            $this->directives[$directive] ?? [],
            $hosts,
        );

        return $this;
    }

    /**
     * Register an inline script hash (e.g. "'sha256-...'"). Applied to
     * script-src in production; in dev 'unsafe-inline' is used instead, since a
     * hash and 'unsafe-inline' cannot coexist (the browser ignores
     * 'unsafe-inline' once any hash is present).
     */
    public function scriptHash(string ...$hashes): self
    {
        $this->scriptHashes = array_merge($this->scriptHashes, $hashes);

        return $this;
    }

    /**
     * Whitelist the Vite dev server. No-op outside dev.
     */
    public function viteDevServer(string $host): self
    {
        if (!$this->isDev || $host === '') {
            return $this;
        }

        $this->add('script-src', $host);
        $this->add('style-src', $host);
        $this->add('font-src', $host);
        $this->add('connect-src', 'wss:', $host);

        return $this;
    }

    /**
     * Set the CSP violation report endpoint (adds report-uri and report-to).
     */
    public function reportUri(string $uri): self
    {
        $this->reportUri = $uri;

        return $this;
    }

    /**
     * JSON value for a Report-To response header pointing at the report endpoint.
     * Returns null when no report URI is set.
     */
    public function reportToHeader(string $group = 'csp-endpoint', int $maxAge = 31536000): ?string
    {
        if ($this->reportUri === null) {
            return null;
        }

        return json_encode([
            'group' => $group,
            'max_age' => $maxAge,
            'endpoints' => [['url' => $this->reportUri]],
            'include_subdomains' => true,
        ], JSON_THROW_ON_ERROR);
    }

    /**
     * Build the directive list for Sherlock: a list of [enabled, name, value].
     *
     * @return list<array{0: bool, 1: string, 2: string}>
     */
    public function directives(): array
    {
        $directives = $this->directives;

        // script-src: hash in production, 'unsafe-inline' in dev. They are
        // mutually exclusive, so pick one per environment.
        $directives['script-src'] = array_merge(
            $directives['script-src'],
            $this->isDev ? ["'unsafe-inline'"] : $this->scriptHashes,
        );

        $result = [];
        foreach (self::ORDER as $name) {
            $tokens = self::dedupe($directives[$name] ?? []);
            if ($tokens === []) {
                continue;
            }
            $result[] = [true, $name, implode(' ', $tokens)];
        }

        if ($this->reportUri !== null) {
            $result[] = [true, 'report-uri', $this->reportUri];
            $result[] = [true, 'report-to', 'csp-endpoint'];
        }

        return $result;
    }

    /**
     * @param list<string> $tokens
     * @return list<string>
     */
    private static function dedupe(array $tokens): array
    {
        return array_values(array_unique(array_filter($tokens, static fn (string $t): bool => $t !== '')));
    }
}
