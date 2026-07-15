<?php

declare(strict_types=1);

namespace sustdev\security\tests\Csp;

use InvalidArgumentException;
use PHPUnit\Framework\TestCase;
use sustdev\security\Csp\GoogleTlds;
use sustdev\security\Csp\ServiceSets;

final class ServiceSetsTest extends TestCase
{
    public function testGoogleTldsListHasNoDuplicatesAndCoversKnownDomains(): void
    {
        $list = GoogleTlds::list();

        self::assertContains('google.com', $list);
        self::assertContains('*.google.com', $list);
        self::assertContains('*.google.com.mx', $list);
        self::assertContains('*.google.nl', $list);
        self::assertSame(array_values(array_unique($list)), $list, 'Google TLD list contains duplicates');
    }

    public function testCatalogueExposesExpectedPublicServices(): void
    {
        $names = ServiceSets::names();

        foreach ([
            'google-tag-manager',
            'google-analytics',
            'google-ads',
            'google-maps',
            'recaptcha',
            'turnstile',
            'meta-pixel',
            'microsoft-clarity',
            'bing-ads',
            'linkedin-insight',
            'cookiebot',
            'mouseflow',
            'trustpilot',
            'cdnjs',
            'jsdelivr',
            'jquery',
            'youtube',
            'gravatar',
            'google-user-content',
            'google-apps-script',
            'ipify',
            'plausible',
            'active-campaign',
            'sentry-sdk',
        ] as $expected) {
            self::assertContains($expected, $names);
        }
    }

    public function testActiveCampaignRequiresHost(): void
    {
        $set = ServiceSets::get('active-campaign', ['host' => 'account.activehosted.com']);
        self::assertContains('account.activehosted.com', $set['connect-src']);

        $this->expectException(InvalidArgumentException::class);
        ServiceSets::get('active-campaign');
    }

    public function testGa4CoversBareAnalyticsApex(): void
    {
        // The wildcard *.analytics.google.com does not match the bare apex, which
        // /g/collect uses when Google Signals is on.
        $connect = ServiceSets::get('google-analytics')['connect-src'];

        self::assertContains('analytics.google.com', $connect);
    }

    public function testYoutubeCoversFullVideoEmbed(): void
    {
        $set = ServiceSets::get('youtube');

        // iframe API script + player.
        self::assertContains('www.youtube.com', $set['script-src']);
        self::assertContains('s.ytimg.com', $set['script-src']);
        // Poster thumbnails.
        self::assertContains('*.ytimg.com', $set['img-src']);
        // Player iframe.
        self::assertContains('*.youtube.com', $set['frame-src']);
        self::assertContains('www.youtube-nocookie.com', $set['frame-src']);
        // Video streams over connect + media, with same-origin media kept.
        self::assertContains('*.googlevideo.com', $set['connect-src']);
        self::assertContains('*.googlevideo.com', $set['media-src']);
        self::assertContains("'self'", $set['media-src']);
    }

    public function testUnknownServiceThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        ServiceSets::get('nope');
    }
}
