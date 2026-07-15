<?php

/**
 * Copy this file to craft/config/security.php and set only the keys that
 * differ from the defaults below. Keys are flat on purpose, so overriding
 * one value does not drop the others.
 */
return [
    // Enforce password complexity on new passwords. Set false to fall back to
    // Craft's own minimal password validation.
    'passwordComplexity' => true,

    // Length bounds for a new password. Raise the minimum to match a tender
    // or policy.
    'passwordMinLength' => 8,
    'passwordMaxLength' => 160,

    // Character classes a new password must contain.
    'passwordRequireLowercase' => true,
    'passwordRequireUppercase' => true,
    'passwordRequireNumber' => true,
    'passwordRequireSymbol' => true,

    // Override the "must contain ..." message. Null uses the built-in,
    // translatable message.
    'passwordMessage' => null,
];
