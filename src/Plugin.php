<?php

namespace sustdev\security;

use craft\base\Model;
use craft\base\Plugin as BasePlugin;
use craft\elements\User;
use craft\events\DefineRulesEvent;
use sustdev\security\models\Settings;
use yii\base\Event;

/**
 * Sustdev Security: server-side security hardening for Craft.
 *
 * Version 1 enforces configurable password complexity on new passwords,
 * server-side only (nothing is rendered on the front end). Configure it in
 * config/security.php; see src/config.php for the available keys.
 *
 * @property-read Settings $settings
 * @method Settings getSettings()
 */
class Plugin extends BasePlugin
{
    public string $schemaVersion = '1.0.0';

    public bool $hasCpSettings = false;

    public bool $hasCpSection = false;

    public static Plugin $plugin;

    public function init(): void
    {
        parent::init();

        self::$plugin = $this;

        Event::on(
            User::class,
            User::EVENT_DEFINE_RULES,
            function (DefineRulesEvent $event) {
                foreach (PasswordComplexity::rules($this->getSettings()) as $rule) {
                    $event->rules[] = $rule;
                }
            },
        );
    }

    protected function createSettingsModel(): ?Model
    {
        return new Settings();
    }

    /**
     * The effective password policy as plain data, for exposing to a front end
     * so a form validates exactly what a server-side save enforces.
     *
     * @return array{enabled: bool, minLength: int, maxLength: int, requireLowercase: bool, requireUppercase: bool, requireNumber: bool, requireSymbol: bool}
     */
    public function getPasswordPolicy(): array
    {
        return PasswordComplexity::policy($this->getSettings());
    }

    /**
     * Human-readable password requirements for the current settings (empty when
     * complexity is disabled).
     */
    public function getPasswordRequirementsText(): string
    {
        return PasswordComplexity::requirementsText($this->getSettings());
    }
}
