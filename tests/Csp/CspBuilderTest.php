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
        // frame-src is seeded with 'self' so a later service frame host does not
        // drop same-origin framing.
        self::assertSame("'self'", $map['frame-src']);
    }

    public function testFrameSrcKeepsSelfWhenServiceAddsFrameHost(): void
    {
        $map = $this->directiveMap(CspBuilder::make()->use('youtube'));

        $frameTokens = explode(' ', $map['frame-src']);
        self::assertContains("'self'", $frameTokens);
        self::assertContains('*.youtube.com', $frameTokens);
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

        $prod = $this->directiveMap(CspBuilder::make(isDev: false)->scriptHash($hash));
        self::assertStringContainsString($hash, $prod['script-src']);
        self::assertStringNotContainsString("'unsafe-inline'", $prod['script-src']);

        $dev = $this->directiveMap(CspBuilder::make(isDev: true)->scriptHash($hash));
        self::assertStringContainsString("'unsafe-inline'", $dev['script-src']);
        self::assertStringNotContainsString($hash, $dev['script-src']);
    }

    public function testScriptSrcAttrIsAbsentUntilAHandlerHashIsRegistered(): void
    {
        // Regression guard for the projects sharing this package: adding
        // script-src-attr to the emission order must not change a single
        // existing policy. Absent means event handlers keep falling back to
        // script-src, which is the behaviour every project has today.
        $map = $this->directiveMap(CspBuilder::make()->use('google-ads')->scriptHash("'sha256-abc123'"));

        self::assertArrayNotHasKey('script-src-attr', $map);
    }

    public function testScriptAttrHashIsScopedToScriptSrcAttrInProduction(): void
    {
        $handlerHash = "'sha256-MhtPZXr7+LpJUY5qtMutB+qWfQtMaPccfe7QXtCcEYc='";
        $scriptHash = "'sha256-abc123'";

        $map = $this->directiveMap(
            CspBuilder::make(isDev: false)->scriptHash($scriptHash)->scriptAttrHash($handlerHash),
        );

        $attrTokens = explode(' ', $map['script-src-attr']);
        self::assertContains("'unsafe-hashes'", $attrTokens);
        self::assertContains($handlerHash, $attrTokens);

        // The handler hash must not leak into script-src, and 'unsafe-hashes'
        // must not either: on script-src it would make every script element
        // hash valid as an event handler body too.
        self::assertStringNotContainsString($handlerHash, $map['script-src']);
        self::assertStringNotContainsString("'unsafe-hashes'", $map['script-src']);

        // Script elements resolve via script-src-elem -> script-src, so
        // declaring script-src-attr must leave script-src untouched.
        self::assertStringContainsString($scriptHash, $map['script-src']);
    }

    public function testScriptAttrHashStaysAbsentInDev(): void
    {
        // In dev script-src carries 'unsafe-inline', which already covers
        // handlers. Emitting script-src-attr there would supersede that and
        // block every handler the hash does not match.
        $map = $this->directiveMap(
            CspBuilder::make(isDev: true)->scriptAttrHash("'sha256-MhtPZXr7+LpJUY5qtMutB+qWfQtMaPccfe7QXtCcEYc='"),
        );

        self::assertArrayNotHasKey('script-src-attr', $map);
        self::assertStringContainsString("'unsafe-inline'", $map['script-src']);
    }

    public function testScriptAttrHashDedupesUnsafeHashesAcrossCalls(): void
    {
        $map = $this->directiveMap(
            CspBuilder::make()->scriptAttrHash("'sha256-aaa='")->scriptAttrHash("'sha256-bbb='"),
        );

        self::assertSame("'unsafe-hashes' 'sha256-aaa=' 'sha256-bbb='", $map['script-src-attr']);
    }

    public function testScriptAttrHashWithNoHashesEmitsNothing(): void
    {
        // 'unsafe-hashes' on its own allows nothing, but emitting the directive
        // would still supersede script-src for handlers and block them all.
        $map = $this->directiveMap(CspBuilder::make()->scriptAttrHash());

        self::assertArrayNotHasKey('script-src-attr', $map);
    }

    public function testAddOwnsScriptSrcAttrTokensInEveryEnvironment(): void
    {
        // add() is the escape hatch: whatever a project puts in a directive is
        // emitted, in dev too. Guarding this in directives() would have made
        // scriptAttrHash() and add() disagree about who controls the directive,
        // so scriptAttrHash() now writes through add() and there is one owner.
        // 'none' is the real use for this: hard-block every inline handler.
        foreach ([true, false] as $isDev) {
            $map = $this->directiveMap(
                CspBuilder::make(isDev: $isDev)->add('script-src-attr', "'none'"),
            );

            self::assertSame("'none'", $map['script-src-attr']);
        }
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
        // The header group must match the report-to directive value, or the
        // browser silently drops reports.
        self::assertSame($map['report-to'], $decoded['group']);
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

    public function testUsingAServiceDoesNotResolveAnUnrelatedRequiredHost(): void
    {
        // Regression guard: requesting any service must not eagerly resolve a
        // different host-required service (active-campaign has no default host).
        $map = $this->directiveMap(CspBuilder::make()->use('google-ads'));

        self::assertStringContainsString('*.doubleclick.net', $map['img-src']);
    }

    public function testAddRejectsUnknownDirective(): void
    {
        // A typo must fail loudly instead of silently dropping the host.
        $this->expectException(InvalidArgumentException::class);
        CspBuilder::make()->add('img-scr', 'example.com');
    }
}
