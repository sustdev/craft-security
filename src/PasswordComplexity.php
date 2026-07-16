<?php

namespace sustdev\security;

use Craft;
use sustdev\security\models\Settings;

/**
 * Builds the validation rules for a new password from the plugin settings, and
 * exposes the same policy as plain data so a front end can validate exactly what
 * a server-side save will enforce (a single source of truth for both sides).
 *
 * The rules are added to the User element's `newPassword` attribute, the
 * plaintext Craft validates when a password is set (registration, change,
 * admin or forgot-password reset, and the CLI). Login authenticates against the stored
 * hash and never runs these rules, so existing accounts keep working; the
 * rules only apply the next time a password is set.
 */
class PasswordComplexity
{
    /**
     * @return array Yii validation rules to append to User::defineRules().
     */
    public static function rules(Settings $settings): array
    {
        if (!$settings->passwordComplexity) {
            return [];
        }

        $min = $settings->passwordMinLength;
        // Guard against a config typo where max < min, which would make the
        // length rule impossible and silently block every password change.
        $max = max($min, $settings->passwordMaxLength);

        $rules = [
            [
                ['newPassword'],
                'string',
                'min' => $min,
                'max' => $max,
                'tooShort' => Craft::t('security', 'Your password must be at least {min} characters.', ['min' => $min]),
                'tooLong' => Craft::t('security', 'Your password may be at most {max} characters.', ['max' => $max]),
            ],
        ];

        $classes = self::characterClasses($settings);

        if ($classes !== []) {
            $lookaheads = implode('', array_column($classes, 'lookahead'));

            $message = $settings->passwordMessage
                ?: Craft::t('security', 'Your password must contain at least {requirements}.', [
                    'requirements' => implode(', ', array_column($classes, 'label')),
                ]);

            // The /D modifier anchors $ to the true end of the string. Without
            // it, PCRE's $ also matches before a trailing newline, which
            // (since . does not match newline) would let a password one
            // character short plus a newline satisfy both this and the length
            // check.
            $rules[] = [
                ['newPassword'],
                'match',
                'pattern' => '/^' . $lookaheads . '.+$/D',
                'message' => $message,
            ];
        }

        return $rules;
    }

    /**
     * The effective password policy as plain data, for exposing to a client so
     * a form can mirror the server rules. When complexity is disabled the plugin
     * enforces nothing extra (Craft's own minimal validation applies), so
     * `enabled` is false and a client should not surface these as requirements.
     *
     * @return array{enabled: bool, minLength: int, maxLength: int, requireLowercase: bool, requireUppercase: bool, requireNumber: bool, requireSymbol: bool}
     */
    public static function policy(Settings $settings): array
    {
        if (!$settings->passwordComplexity) {
            // The plugin adds no rules when complexity is off (Craft's own
            // minimal validation still runs server-side). Report an inactive
            // policy with no length or class constraints, so a client that
            // mirrors these fields cannot reject a password the plugin would
            // accept, even if it ignores the `enabled` flag.
            return [
                'enabled' => false,
                'minLength' => 0,
                'maxLength' => PHP_INT_MAX,
                'requireLowercase' => false,
                'requireUppercase' => false,
                'requireNumber' => false,
                'requireSymbol' => false,
            ];
        }

        $min = $settings->passwordMinLength;

        return [
            'enabled' => true,
            'minLength' => $min,
            // Mirror rules(): max is clamped to at least min.
            'maxLength' => max($min, $settings->passwordMaxLength),
            'requireLowercase' => $settings->passwordRequireLowercase,
            'requireUppercase' => $settings->passwordRequireUppercase,
            'requireNumber' => $settings->passwordRequireNumber,
            'requireSymbol' => $settings->passwordRequireSymbol,
        ];
    }

    /**
     * Human-readable requirements (e.g. "at least 8 characters, a number"),
     * built from the same settings and labels as the validation rules. Returns
     * an empty string when complexity is disabled.
     */
    public static function requirementsText(Settings $settings): string
    {
        if (!$settings->passwordComplexity) {
            return '';
        }

        $parts = [
            Craft::t('security', 'at least {min} characters', ['min' => $settings->passwordMinLength]),
        ];
        foreach (self::characterClasses($settings) as $class) {
            $parts[] = $class['label'];
        }

        return implode(', ', $parts);
    }

    /**
     * The required character classes for the current settings: the regex
     * lookahead that enforces each and its human-readable label. Single source
     * for both the validation pattern and the requirements description.
     *
     * @return list<array{lookahead: string, label: string}>
     */
    private static function characterClasses(Settings $settings): array
    {
        $classes = [];

        if ($settings->passwordRequireLowercase) {
            $classes[] = ['lookahead' => '(?=.*[a-z])', 'label' => Craft::t('security', 'a lowercase letter')];
        }
        if ($settings->passwordRequireUppercase) {
            $classes[] = ['lookahead' => '(?=.*[A-Z])', 'label' => Craft::t('security', 'an uppercase letter')];
        }
        if ($settings->passwordRequireNumber) {
            $classes[] = ['lookahead' => '(?=.*\d)', 'label' => Craft::t('security', 'a number')];
        }
        if ($settings->passwordRequireSymbol) {
            // Exclude whitespace, so a space or tab does not count as the
            // required special character.
            $classes[] = ['lookahead' => '(?=.*[^a-zA-Z0-9\s])', 'label' => Craft::t('security', 'a special character')];
        }

        return $classes;
    }
}
