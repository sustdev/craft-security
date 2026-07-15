<?php

namespace sustdev\security\models;

use craft\base\Model;

/**
 * Flat settings so that config/security.php can override any single value
 * without replacing a whole nested array (which would drop the other
 * defaults). Set the ones a site needs in config/security.php.
 */
class Settings extends Model
{
    /**
     * Enforce password complexity on new passwords. Turn off to fall back to
     * Craft's own minimal password validation.
     */
    public bool $passwordComplexity = true;

    /**
     * Minimum length for a new password. Raise it to match a tender or policy.
     */
    public int $passwordMinLength = 8;

    /**
     * Maximum length for a new password.
     */
    public int $passwordMaxLength = 160;

    public bool $passwordRequireLowercase = true;

    public bool $passwordRequireUppercase = true;

    public bool $passwordRequireNumber = true;

    public bool $passwordRequireSymbol = true;

    /**
     * Override the default "must contain ..." message shown when the
     * complexity check fails. Null uses the built-in message.
     */
    public ?string $passwordMessage = null;

    public function defineRules(): array
    {
        return [
            [
                ['passwordComplexity', 'passwordRequireLowercase', 'passwordRequireUppercase', 'passwordRequireNumber', 'passwordRequireSymbol'],
                'boolean',
            ],
            [['passwordMinLength', 'passwordMaxLength'], 'integer', 'min' => 1],
            [['passwordMessage'], 'string'],
        ];
    }
}
