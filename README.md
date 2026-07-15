# Sustdev Security

Server-side security hardening for Craft CMS 5.

## Version 1: password complexity

Enforces configurable complexity on new passwords, server-side only. Nothing is
rendered on the front end. The rules apply to the `newPassword` attribute, so
they run when a password is set (registration, change, admin or
forgot-password reset). Login authenticates against the stored hash and never
runs them, so raising the policy does not lock out existing accounts; the
stricter rules apply the next time each user sets a password.

## Configuration

Everything is driven by a config file, there are no control-panel settings.
Copy `src/config.php` to `config/security.php` and set only what differs from
the defaults:

```php
return [
    'passwordMinLength' => 12,
];
```

Available keys: `passwordComplexity`, `passwordMinLength`, `passwordMaxLength`,
`passwordRequireLowercase`, `passwordRequireUppercase`, `passwordRequireNumber`,
`passwordRequireSymbol`, `passwordMessage`. See `src/config.php` for the
defaults and what each does.

Messages are translatable (English source, Dutch included); override the
complexity message per site with `passwordMessage`.
