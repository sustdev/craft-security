<?php

declare(strict_types=1);

namespace sustdev\security\tests\Csp;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use sustdev\security\Csp\CspBuilder;

final class CspBuilderTest extends TestCase
{
    /**
     * @return array<string, string> directive name => value
     */
    private function directiveMap(CspBuilder $csp): array
    {
        $map = [];
        foreach ($csp->directives() as [$enabled, $name, $value]) {
            self::assertTrue($enabled);
            $map[$name] = $value;
        }

        return $map;
    }

    public function testBaseDirectivesArePresent(): void
    {
        $map = $this->directiveMap(CspBuilder::make());

        self::assertSame("'self'", $map['default-src']);
        self::assertSame("'none'", $map['object-src']);
        self::assertSame("'self'", $map['base-uri']);
        self::assertSame("'self'", $map['frame-ancestors']);
        self::assertStringContainsString('blob:', $map['worker-src']);
        // No third-party service used, so no frame-src is emitted.
        self::assertArrayNotHasKey('frame-src', $map);
    }

    public function testGoogleAdsSpreadsTldListIntoImgAndConnect(): void
    {
        $map = $this->directiveMap(CspBuilder::make()->use('google-ads'));

        self::assertStringContainsString('*.google.com.mx', $map['img-src']);
        self::assertStringContainsString('*.google.com.mx', $map['connect-src']);
        self::assertStringContainsString('*.doubleclick.net', $map['frame-src']);
    }

    public function testHostsAreDeduplicated(): void
    {
        $map = $this->directiveMap(
            CspBuilder::make()->add('img-src', 'example.com', 'example.com'),
        );

        self::assertSame(1, substr_count($map['img-src'], 'example.com'));
    }

    public function testYoutubeSetHasCleanTokens(): void
    {
        // Guards against a real-world bug where a trailing comma inside the
        // string ("*.youtube.com,") made the token never match.
        $map = $this->directiveMap(CspBuilder::make()->use('youtube'));

        $frameTokens = explode(' ', $map['frame-src']);
        self::assertContains('*.youtube.com', $frameTokens);
        self::assertNotContains('*.youtube.com,', $frameTokens);
        self::assertStringContainsString('*.ytimg.com', $map['img-src']);
    }

    public function testPlausibleDefaultsToPublicHostAndCanBeOverridden(): void
    {
        $default = $this->directiveMap(CspBuilder::make()->use('plausible'));
        self::assertStringContainsString('plausible.io', $default['connect-src']);

        $selfHosted = $this->directiveMap(
            CspBuilder::make()->use('plausible', ['host' => 'privacy.example.com']),
        );
        self::assertStringContainsString('privacy.example.com', $selfHosted['connect-src']);
        self::assertStringNotContainsString('plausible.io', $selfHosted['connect-src']);
    }

    public function testScriptHashUsedInProductionOnly(): void
    {
        $hash = "'sha256-abc123'";

        $prod = $this->directiveMap(CspBuilder::make(isDev: false, isProduction: true)->scriptHash($hash));
        self::assertStringContainsString($hash, $prod['script-src']);
        self::assertStringNotContainsString("'unsafe-inline'", $prod['script-src']);

        $dev = $this->directiveMap(CspBuilder::make(isDev: true)->scriptHash($hash));
        self::assertStringContainsString("'unsafe-inline'", $dev['script-src']);
        self::assertStringNotContainsString($hash, $dev['script-src']);
    }

    public function testViteDevServerOnlyAppliesInDev(): void
    {
        $host = 'https://project.ddev.site:3000';

        $dev = $this->directiveMap(CspBuilder::make(isDev: true)->viteDevServer($host));
        self::assertStringContainsString($host, $dev['script-src']);
        self::assertStringContainsString('wss:', $dev['connect-src']);

        $prod = $this->directiveMap(CspBuilder::make(isDev: false)->viteDevServer($host));
        self::assertStringNotContainsString($host, $prod['script-src']);
    }

    public function testReportUriAddsReportDirectivesAndHeader(): void
    {
        $uri = 'https://ingest.example.com/security/?key=abc';
        $csp = CspBuilder::make()->reportUri($uri);
        $map = $this->directiveMap($csp);

        self::assertSame($uri, $map['report-uri']);
        self::assertSame('csp-endpoint', $map['report-to']);

        $header = $csp->reportToHeader();
        self::assertNotNull($header);
        self::assertJson($header);
        // json_encode escapes slashes, so decode rather than substring-match.
        $decoded = json_decode($header, true);
        self::assertSame($uri, $decoded['endpoints'][0]['url']);
        self::assertSame('csp-endpoint', $decoded['group']);
    }

    public function testReportToHeaderNullWithoutReportUri(): void
    {
        self::assertNull(CspBuilder::make()->reportToHeader());
    }

    public function testUnknownServiceThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        CspBuilder::make()->use('not-a-real-service');
    }
}
