<?php
/**
 * Auth: validates incoming webhook requests via Bearer Token and/or HMAC signature.
 */
class Auth
{
    /**
     * Validate the request against the configured authentication methods.
     *
     * Returns true if the request is authenticated, false otherwise.
     * Sets $usedHeader to the header name that was checked (for failure logging).
     *
     * @param array  $config  The 'auth' section of config.php
     * @param string $rawBody The raw request body (needed for HMAC)
     * @param string $usedHeader  Output: which header was attempted
     */
    public static function validate(array $config, string $rawBody, string &$usedHeader = ''): bool
    {
        $bearerToken = $config['bearer_token'] ?? '';
        $hmacSecret  = $config['hmac_secret']  ?? '';
        $requireBoth = (bool) ($config['require_both'] ?? false);

        $bearerEnabled = $bearerToken !== '';
        $hmacEnabled   = $hmacSecret  !== '';

        $bearerValid = false;
        $hmacValid   = false;

        // --- Bearer Token ---
        if ($bearerEnabled) {
            $usedHeader = 'Authorization';
            $header = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : '';
            if (strncmp($header, 'Bearer ', 7) === 0) {
                $provided = substr($header, 7);
                $bearerValid = hash_equals($bearerToken, $provided);
            }
        }

        // --- HMAC Signature ---
        if ($hmacEnabled) {
            $usedHeader = 'X-Webhook-Signature';
            $header = isset($_SERVER['HTTP_X_WEBHOOK_SIGNATURE']) ? $_SERVER['HTTP_X_WEBHOOK_SIGNATURE'] : '';
            if (strncmp($header, 'sha256=', 7) === 0) {
                $provided  = substr($header, 7);
                $expected  = hash_hmac('sha256', $rawBody, $hmacSecret);
                $hmacValid = hash_equals($expected, $provided);
            }
        }

        // If both headers were checked, reflect that in usedHeader
        if ($bearerEnabled && $hmacEnabled) {
            $usedHeader = 'Authorization + X-Webhook-Signature';
        }

        // Determine overall result
        if ($requireBoth) {
            // Both enabled methods must pass
            $bearerOk = !$bearerEnabled || $bearerValid;
            $hmacOk   = !$hmacEnabled   || $hmacValid;
            return $bearerOk && $hmacOk;
        }

        // At least one enabled method must pass
        if (!$bearerEnabled && !$hmacEnabled) {
            // No auth configured: deny everything
            return false;
        }

        return $bearerValid || $hmacValid;
    }

    /**
     * Log a failed authentication attempt to the auth_failures table.
     *
     * @param Database $db
     * @param string   $ip
     * @param string   $headerUsed
     */
    public static function logFailure($db, string $ip, string $headerUsed): void
    {
        $db->execute(
            'INSERT INTO auth_failures (ip, header_used) VALUES (:ip, :header)',
            [':ip' => $ip, ':header' => $headerUsed ?: null]
        );
    }
}
