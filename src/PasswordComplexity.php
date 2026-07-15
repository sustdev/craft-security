<?php

namespace sustdev\security;

use Craft;
use sustdev\security\models\Settings;

/**
 * Builds the validation rules for a new password from the plugin settings.
 *
 * The rules are added to the User element's `newPassword` attribute, the
 * plaintext Craft validates when a password is set (registration, change,
 * admin or forgot-password reset). Login authenticates against the stored
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

        $rules = [
            [
                ['newPassword'],
                'string',
                'min' => $settings->passwordMinLength,
                'max' => $settings->passwordMaxLength,
                'tooShort' => Craft::t('security', 'Your password must be at least {min} characters.', ['min' => $settings->passwordMinLength]),
                'tooLong' => Craft::t('security', 'Your password may be at most {max} characters.', ['max' => $settings->passwordMaxLength]),
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
            $lookaheads .= '(?=.*[^a-zA-Z0-9])';
            $requirements[] = Craft::t('security', 'a special character');
        }

        if ($lookaheads !== '') {
            $message = $settings->passwordMessage
                ?: Craft::t('security', 'Your password must contain at least {requirements}.', [
                    'requirements' => implode(', ', $requirements),
                ]);

            $rules[] = [
                ['newPassword'],
                'match',
                'pattern' => '/^' . $lookaheads . '.+$/',
                'message' => $message,
            ];
        }

        return $rules;
    }
}
