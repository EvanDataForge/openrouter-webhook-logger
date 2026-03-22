<?php
// Copy this file to config.php and fill in your values.
// NEVER commit config.php to version control!

return [
    // Database connection
    'db' => [
        'host'    => 'localhost',
        'name'    => 'DEINE_DATENBANK',
        'user'    => 'DEIN_BENUTZER',
        'pass'    => 'DEIN_PASSWORT',
        'charset' => 'utf8mb4',
    ],

    // Authentication
    // Leave bearer_token or hmac_secret empty ('') to disable that method.
    // require_both = true: both methods must pass (stricter).
    // require_both = false: at least one method must pass (default).
    'auth' => [
        'bearer_token'  => 'DEIN_BEARER_TOKEN',
        'hmac_secret'   => 'DEIN_HMAC_SECRET',
        'require_both'  => false,
    ],

    // Logging options
    // log_raw_payload: stores the full JSON body in the database (privacy risk!)
    // log_auth_failures: logs failed auth attempts with IP address
    'log_raw_payload'   => false,
    'log_auth_failures' => true,

    // Dashboard viewer password (for /mywebhookviewer/)
    'viewer_password' => 'DEIN_VIEWER_PASSWORT',

    // Optional local viewer debugging:
    // Point the dashboard frontend to a mock API instead of the PHP/MySQL backend.
    // Example: 'http://127.0.0.1:8765'
    'viewer_api_base' => '',

    // Only enable locally when you want to skip the login form.
    'viewer_disable_auth' => false,
];
