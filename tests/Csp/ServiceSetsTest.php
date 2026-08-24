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
            'google-maps-embed',
            'recaptcha',
            'turnstile',
            'mailerlite',
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
            'vimeo',
            'gravatar',
            'google-user-content',
            'google-apps-script',
            'ipify',
            'plausible',
            'active-campaign',
            'sentry-sdk',
            'algolia',
            'mapbox',
            'matomo',
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

    public function testMatomoRequiresHost(): void
    {
        $set = ServiceSets::get('matomo', ['host' => 'example.matomo.cloud']);
        self::assertContains('example.matomo.cloud', $set['script-src']);
        self::assertContains('example.matomo.cloud', $set['connect-src']);
        self::assertContains('example.matomo.cloud', $set['img-src']);

        $this->expectException(InvalidArgumentException::class);
        ServiceSets::get('matomo');
    }

    public function testAlgoliaAndMapboxHosts(): void
    {
        $algolia = ServiceSets::get('algolia');
        self::assertContains('*.algolia.net', $algolia['connect-src']);
        self::assertContains('*.algolianet.com', $algolia['connect-src']);

        $mapbox = ServiceSets::get('mapbox');
        self::assertContains('api.mapbox.com', $mapbox['connect-src']);
        self::assertContains('events.mapbox.com', $mapbox['connect-src']);
        self::assertContains('api.mapbox.com', $mapbox['img-src']);
        // The legacy tiles.mapbox.com host is deliberately not carried; current
        // GL JS consolidates all tile traffic under api.mapbox.com.
        self::assertNotContains('*.tiles.mapbox.com', $mapbox['connect-src']);
    }

    public function testGa4CoversBareAnalyticsApex(): void
    {
        // The wildcard *.analytics.google.com does not match the bare apex, which
        // /g/collect uses when Google Signals is on.
        $connect = ServiceSets::get('google-analytics')['connect-src'];

        self::assertContains('analytics.google.com', $connect);
    }

    public function testYoutubeCoversParentScopedEmbedHosts(): void
    {
        $set = ServiceSets::get('youtube');

        // JS IFrame Player API script, loaded by the embedding page.
        self::assertContains('www.youtube.com', $set['script-src']);
        self::assertContains('s.ytimg.com', $set['script-src']);
        // Poster thumbnail the page renders.
        self::assertContains('*.ytimg.com', $set['img-src']);
        // The player iframe.
        self::assertContains('*.youtube.com', $set['frame-src']);
        self::assertContains('www.youtube-nocookie.com', $set['frame-src']);
        // The short link the player navigates to when a viewer follows the share
        // or title link. A separate registrable domain, so *.youtube.com misses it.
        self::assertContains('youtu.be', $set['frame-src']);
        // The in-iframe video streams (*.googlevideo.com) load in the iframe's
        // own context, not the parent, so the set must not add these directives.
        self::assertArrayNotHasKey('connect-src', $set);
        self::assertArrayNotHasKey('media-src', $set);
    }

    public function testVimeoCoversParentScopedEmbedHosts(): void
    {
        $set = ServiceSets::get('vimeo');

        // Player SDK script, loaded by the embedding page.
        self::assertContains('player.vimeo.com', $set['script-src']);
        // Poster thumbnail the page renders.
        self::assertContains('i.vimeocdn.com', $set['img-src']);
        // The player iframe.
        self::assertContains('player.vimeo.com', $set['frame-src']);
        // The in-iframe player assets (f.vimeocdn.com) and video streams load in
        // the iframe's own context, not the parent, so the set must not add
        // these hosts or directives.
        self::assertArrayNotHasKey('connect-src', $set);
        self::assertArrayNotHasKey('media-src', $set);
        self::assertNotContains('f.vimeocdn.com', $set['script-src']);
    }

    public function testGoogleMapsEmbedCoversOnlyTheFrameNavigation(): void
    {
        $set = ServiceSets::get('google-maps-embed');

        // The iframe src names maps.google.com and lands on www.google.com after
        // the redirect. frame-src matches the origin after the redirect, so
        // dropping either host breaks the embed.
        self::assertContains('maps.google.com', $set['frame-src']);
        self::assertContains('www.google.com', $set['frame-src']);

        // Everything else the map pulls (the Maps API, gstatic tiles, Google
        // Fonts) is requested by Google's document inside the iframe, under
        // Google's policy. The embedding page grants none of it.
        self::assertSame(['frame-src'], array_keys($set));
    }

    public function testGoogleMapsEmbedIsNotTheJavaScriptApiSet(): void
    {
        // The two Maps variants are separate on purpose: a plain embed needs one
        // directive, while the JS API set grants six hosts an embed never asks for.
        $embed = ServiceSets::get('google-maps-embed');
        $api = ServiceSets::get('google-maps');

        self::assertArrayNotHasKey('script-src', $embed);
        self::assertContains('maps.googleapis.com', $api['script-src']);
        // The JS API set frames www.google.com but not maps.google.com, which is
        // why an embed cannot simply use it.
        self::assertNotContains('maps.google.com', $api['frame-src']);
    }

    public function testUnknownServiceThrows(): void
    {
        $this->expectException(InvalidArgumentException::class);
        ServiceSets::get('nope');
    }
}
