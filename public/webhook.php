<?php
/**
 * webhook.php – public endpoint for OpenRouter OTLP traceability webhooks.
 *
 * Supported auth methods: Bearer Token, HMAC-SHA256 signature.
 * See config/config.example.php for configuration options.
 */

// Suppress PHP errors from leaking into HTTP responses
require_once __DIR__ . '/../src/Logger.php';
Logger::suppressErrorOutput();

require_once __DIR__ . '/../src/Database.php';
require_once __DIR__ . '/../src/Auth.php';
require_once __DIR__ . '/../src/OtlpParser.php';

// --- Load config ---
$configFile = __DIR__ . '/../config/config.php';
if (!file_exists($configFile)) {
    Logger::jsonResponse(500, ['error' => 'Server configuration error']);
}
$config = require $configFile;

// --- Only accept POST ---
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    Logger::jsonResponse(405, ['error' => 'Method Not Allowed']);
}

// --- Read raw body ---
$rawBody = file_get_contents('php://input');
if ($rawBody === false) {
    $rawBody = '';
}

// --- Authenticate ---
$usedHeader = '';
$isValid = Auth::validate($config['auth'], $rawBody, $usedHeader);

if (!$isValid) {
    if (!empty($config['log_auth_failures'])) {
        try {
            $db = new Database($config['db']);
            Auth::logFailure($db, getClientIp(), $usedHeader);
        } catch (Exception $e) {
            // Logging failure should not change the response
        }
    }
    Logger::jsonResponse(401, ['error' => 'Unauthorized']);
}

// --- Handle test-connection ping (no DB writes) ---
$isTestConnection = isset($_SERVER['HTTP_X_TEST_CONNECTION'])
    && strtolower($_SERVER['HTTP_X_TEST_CONNECTION']) === 'true';

if ($isTestConnection) {
    Logger::jsonResponse(200, ['status' => 'ok']);
}

// --- Decode JSON (before opening DB connection) ---
$payload = json_decode($rawBody, true);
if ($payload === null && $rawBody !== '') {
    Logger::jsonResponse(400, ['error' => 'Invalid JSON']);
}
if (!is_array($payload)) {
    $payload = [];
}

// Empty resourceSpans – nothing to store, no DB needed
if (empty($payload['resourceSpans'])) {
    Logger::jsonResponse(200, ['status' => 'ok', 'spans' => 0]);
}

// --- Process payload (open DB only when spans are present) ---
try {
    $spans = OtlpParser::parse($payload);

    $db = new Database($config['db']);

    // Insert spans into DB
    $rawPayloadValue = !empty($config['log_raw_payload']) ? $rawBody : null;

    $sql = '
        INSERT IGNORE INTO traces
            (trace_id, span_id, openrouter_trace_id,
             request_model, response_model, provider_name, provider_slug,
             operation_name, span_type, finish_reason, finish_reasons, trace_name,
             input_tokens, output_tokens, cached_tokens, reasoning_tokens,
             audio_tokens, video_tokens, image_tokens,
             input_cost_usd, output_cost_usd, total_cost_usd,
             input_unit_price, output_unit_price,
             started_at, ended_at, duration_ms,
             span_input, span_output, trace_input, trace_output,
             gen_ai_prompt, gen_ai_completion,
             api_key_name, user_id, entity_id, raw_payload)
        VALUES
            (:trace_id, :span_id, :openrouter_trace_id,
             :request_model, :response_model, :provider_name, :provider_slug,
             :operation_name, :span_type, :finish_reason, :finish_reasons, :trace_name,
             :input_tokens, :output_tokens, :cached_tokens, :reasoning_tokens,
             :audio_tokens, :video_tokens, :image_tokens,
             :input_cost_usd, :output_cost_usd, :total_cost_usd,
             :input_unit_price, :output_unit_price,
             :started_at, :ended_at, :duration_ms,
             :span_input, :span_output, :trace_input, :trace_output,
             :gen_ai_prompt, :gen_ai_completion,
             :api_key_name, :user_id, :entity_id, :raw_payload)
    ';

    foreach ($spans as $span) {
        $db->execute($sql, [
            ':trace_id'             => $span['trace_id'],
            ':span_id'              => $span['span_id'],
            ':openrouter_trace_id'  => $span['openrouter_trace_id'],
            ':request_model'        => $span['request_model'],
            ':response_model'       => $span['response_model'],
            ':provider_name'        => $span['provider_name'],
            ':provider_slug'        => $span['provider_slug'],
            ':operation_name'       => $span['operation_name'],
            ':span_type'            => $span['span_type'],
            ':finish_reason'        => $span['finish_reason'],
            ':finish_reasons'       => $span['finish_reasons'],
            ':trace_name'           => $span['trace_name'],
            ':input_tokens'         => $span['input_tokens'],
            ':output_tokens'        => $span['output_tokens'],
            ':cached_tokens'        => $span['cached_tokens'],
            ':reasoning_tokens'     => $span['reasoning_tokens'],
            ':audio_tokens'         => $span['audio_tokens'],
            ':video_tokens'         => $span['video_tokens'],
            ':image_tokens'         => $span['image_tokens'],
            ':input_cost_usd'       => $span['input_cost_usd'],
            ':output_cost_usd'      => $span['output_cost_usd'],
            ':total_cost_usd'       => $span['total_cost_usd'],
            ':input_unit_price'     => $span['input_unit_price'],
            ':output_unit_price'    => $span['output_unit_price'],
            ':started_at'           => $span['started_at'],
            ':ended_at'             => $span['ended_at'],
            ':duration_ms'          => $span['duration_ms'],
            ':span_input'           => $span['span_input'],
            ':span_output'          => $span['span_output'],
            ':trace_input'          => $span['trace_input'],
            ':trace_output'         => $span['trace_output'],
            ':gen_ai_prompt'        => $span['gen_ai_prompt'],
            ':gen_ai_completion'    => $span['gen_ai_completion'],
            ':api_key_name'         => $span['api_key_name'],
            ':user_id'              => $span['user_id'],
            ':entity_id'            => $span['entity_id'],
            ':raw_payload'          => $rawPayloadValue,
        ]);
    }

    Logger::jsonResponse(200, ['status' => 'ok', 'spans' => count($spans)]);

} catch (PDOException $e) {
    error_log('Webhook DB error: ' . $e->getMessage());
    Logger::jsonResponse(500, ['error' => 'Internal Server Error']);
} catch (Exception $e) {
    error_log('Webhook error: ' . $e->getMessage());
    Logger::jsonResponse(500, ['error' => 'Internal Server Error']);
}

// ---------------------------------------------------------------------------

/**
 * Return the client's IP address.
 */
function getClientIp(): string
{
    // Trust X-Forwarded-For only from known proxy setups;
    // on shared hosting without a trusted proxy just use REMOTE_ADDR.
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        // Take the first IP in a potential chain
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($parts[0]);
    }
    return isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '0.0.0.0';
}
