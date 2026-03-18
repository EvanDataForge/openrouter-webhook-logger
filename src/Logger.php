<?php
/**
 * Logger: HTTP response helpers and error suppression.
 */
class Logger
{
    /**
     * Send a JSON response and terminate.
     *
     * @param int   $statusCode HTTP status code
     * @param array $data       Data to JSON-encode
     */
    public static function jsonResponse(int $statusCode, array $data): void
    {
        http_response_code($statusCode);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($data);
        exit;
    }

    /**
     * Disable PHP error output to the browser.
     * Should be called at the start of public-facing scripts.
     */
    public static function suppressErrorOutput(): void
    {
        ini_set('display_errors', '0');
        ini_set('display_startup_errors', '0');
        error_reporting(E_ALL);
    }
}
