<?php

namespace sustdev\security;

use Craft;
use sustdev\security\models\Settings;

/**
 * Builds the validation rules for a new password from the plugin settings.
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

        $lookaheads = '';
        $requirements = [];

        if ($settings->passwordRequireLowercase) {
            $lookaheads .= '(?=.*[a-z])';
            $requirements[] = Craft::t('security', 'a lowercase letter');
        }
        if ($settings->passwordRequireUppercase) {
            $lookaheads .= '(?=.*[A-Z])';
            $requirements[] = Craft::t('security', 'an uppercase letter');
        }
        if ($settings->passwordRequireNumber) {
            $lookaheads .= '(?=.*\d)';
            $requirements[] = Craft::t('security', 'a number');
        }
        if ($settings->passwordRequireSymbol) {
            // Exclude whitespace, so a space or tab does not count as the
            // required special character.
            $lookaheads .= '(?=.*[^a-zA-Z0-9\s])';
            $requirements[] = Craft::t('security', 'a special character');
        }

        if ($lookaheads !== '') {
            $message = $settings->passwordMessage
                ?: Craft::t('security', 'Your password must contain at least {requirements}.', [
                    'requirements' => implode(', ', $requirements),
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
}
