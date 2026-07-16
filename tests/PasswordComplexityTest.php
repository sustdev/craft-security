<?php

declare(strict_types=1);

namespace sustdev\security\tests;

use PHPUnit\Framework\TestCase;
use sustdev\security\models\Settings;
use sustdev\security\PasswordComplexity;

final class PasswordComplexityTest extends TestCase
{
    public function testPolicyReflectsEnabledDefaults(): void
    {
        $policy = PasswordComplexity::policy(new Settings());

        self::assertTrue($policy['enabled']);
        self::assertSame(8, $policy['minLength']);
        self::assertSame(160, $policy['maxLength']);
        self::assertTrue($policy['requireLowercase']);
        self::assertTrue($policy['requireUppercase']);
        self::assertTrue($policy['requireNumber']);
        self::assertTrue($policy['requireSymbol']);
    }

    public function testPolicyIsDisabledAndClassesOffWhenComplexityOff(): void
    {
        $settings = new Settings();
        $settings->passwordComplexity = false;
        // These stay true in config but must not surface while complexity is off.
        $settings->passwordRequireSymbol = true;

        $policy = PasswordComplexity::policy($settings);

        self::assertFalse($policy['enabled']);
        self::assertFalse($policy['requireLowercase']);
        self::assertFalse($policy['requireUppercase']);
        self::assertFalse($policy['requireNumber']);
        self::assertFalse($policy['requireSymbol']);
    }

    public function testPolicyMatchesTunedMinOnlyPolicy(): void
    {
        // The "min 8, no character classes" tuning a project uses to match a
        // client that only checks length.
        $settings = new Settings();
        $settings->passwordRequireLowercase = false;
        $settings->passwordRequireUppercase = false;
        $settings->passwordRequireNumber = false;
        $settings->passwordRequireSymbol = false;

        $policy = PasswordComplexity::policy($settings);

        self::assertTrue($policy['enabled']);
        self::assertSame(8, $policy['minLength']);
        self::assertFalse($policy['requireNumber']);
    }

    public function testPolicyClampsMaxToAtLeastMin(): void
    {
        $settings = new Settings();
        $settings->passwordMinLength = 20;
        $settings->passwordMaxLength = 10;

        self::assertSame(20, PasswordComplexity::policy($settings)['maxLength']);
    }

    public function testRulesAreEmptyWhenComplexityDisabled(): void
    {
        $settings = new Settings();
        $settings->passwordComplexity = false;

        self::assertSame([], PasswordComplexity::rules($settings));
    }

    public function testRequirementsTextIsEmptyWhenComplexityDisabled(): void
    {
        $settings = new Settings();
        $settings->passwordComplexity = false;

        self::assertSame('', PasswordComplexity::requirementsText($settings));
    }
}
