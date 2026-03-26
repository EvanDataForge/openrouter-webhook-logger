<?php
// Globaler JSON-Error-Handler für API-Requests (_action)
if (isset($_GET['_action'])) {
    set_exception_handler(function ($e) {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        echo json_encode([
            'error' => 'Uncaught Exception',
            'debug' => [
                'message' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $e->getTraceAsString(),
            ]
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    });
    set_error_handler(function ($errno, $errstr, $errfile, $errline) {
        http_response_code(500);
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        echo json_encode([
            'error' => 'PHP Error',
            'debug' => [
                'errno' => $errno,
                'errstr' => $errstr,
                'file' => $errfile,
                'line' => $errline
            ]
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    });
}
/**
 * OTLP Trace Dashboard — webhookviewer.php
 * Read-only UI for the traces table.
 * Access via /mywebhookviewer/ or directly as /webhookviewer.php
 */

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

require __DIR__ . '/../src/Database.php';
$config = require __DIR__ . '/../config/config.php';

function viewer_flag_enabled($value): bool
{
    if (is_bool($value)) return $value;
    $normalized = strtolower(trim((string)$value));
    return in_array($normalized, ['1', 'true', 'yes', 'on'], true);
}

function viewer_env_or_config(string $envKey, array $config, string $configKey, string $default = ''): string
{
    $env = getenv($envKey);
    if ($env !== false && $env !== '') {
        return trim((string)$env);
    }
    $value = $config[$configKey] ?? $default;
    return is_string($value) ? trim($value) : $default;
}

$VIEWER_AUTH_DISABLED = viewer_flag_enabled(
    getenv('VIEWER_DISABLE_AUTH') !== false
        ? getenv('VIEWER_DISABLE_AUTH')
        : ($config['viewer_disable_auth'] ?? false)
);
$VIEWER_API_BASE = rtrim(
    viewer_env_or_config('VIEWER_API_BASE', $config, 'viewer_api_base'),
    '/'
);

session_set_cookie_params([
    'lifetime' => 0,
    'path'     => '/',
    'secure'   => isset($_SERVER['HTTPS']),
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

// ---------------------------------------------------------------------------
// Remember-Token Store
// ---------------------------------------------------------------------------

class TokenStore
{
    private const PATH   = __DIR__ . '/../data/tokens.json';
    private const TTL    = 30 * 24 * 3600; // 30 Tage in Sekunden
    private const COOKIE = 'remember_token';

    /** Erzeugt ein neues Token, speichert den SHA-256-Hash und setzt das Cookie. */
    public static function create(): void
    {
        $raw  = bin2hex(random_bytes(32));
        $hash = hash('sha256', $raw);
        $data = self::load();
        $data[$hash] = ['expires_at' => time() + self::TTL];
        self::save($data);
        self::setCookie($raw, time() + self::TTL);
    }

    /** Prüft das Raw-Token aus dem Cookie gegen den gespeicherten Hash + Ablaufzeit. */
    public static function validate(): bool
    {
        $raw = $_COOKIE[self::COOKIE] ?? '';
        if ($raw === '') {
            return false;
        }
        $hash = hash('sha256', $raw);
        $data = self::load();
        if (!isset($data[$hash])) {
            return false;
        }
        if ($data[$hash]['expires_at'] < time()) {
            unset($data[$hash]);
            self::save($data);
            return false;
        }
        return true;
    }

    /** Widerruft das Token aus dem Cookie und löscht das Cookie. */
    public static function revoke(): void
    {
        $raw = $_COOKIE[self::COOKIE] ?? '';
        if ($raw !== '') {
            $hash = hash('sha256', $raw);
            $data = self::load();
            unset($data[$hash]);
            self::save($data);
        }
        self::setCookie('', time() - 3600);
    }

    private static function load(): array
    {
        if (!file_exists(self::PATH)) {
            return [];
        }
        $data = json_decode(file_get_contents(self::PATH), true) ?? [];
        $now  = time();
        return array_filter($data, fn($v) => $v['expires_at'] >= $now);
    }

    private static function save(array $data): void
    {
        $dir = dirname(self::PATH);
        if (!is_dir($dir)) {
            mkdir($dir, 0750, true);
        }
        $tmp = self::PATH . '.tmp';
        file_put_contents($tmp, json_encode($data), LOCK_EX);
        rename($tmp, self::PATH);
    }

    private static function setCookie(string $value, int $expires): void
    {
        setcookie(self::COOKIE, $value, [
            'expires'  => $expires,
            'path'     => '/',
            'secure'   => isset($_SERVER['HTTPS']),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

function viewer_check_auth(): bool
{
    global $VIEWER_AUTH_DISABLED;
    if ($VIEWER_AUTH_DISABLED) {
        return true;
    }
    if (empty($_SESSION['viewer_authed']) && TokenStore::validate()) {
        session_regenerate_id(true);
        $_SESSION['viewer_authed'] = true;
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
        }
    }
    return !empty($_SESSION['viewer_authed']);
}

function viewer_do_login(string $password, array $config): bool
{
    $expected = $config['viewer_password'] ?? '';
    if ($expected === '' || !hash_equals($expected, $password)) {
        sleep(1);
        return false;
    }
    session_regenerate_id(true);
    $_SESSION['viewer_authed'] = true;
    $_SESSION['csrf_token']    = bin2hex(random_bytes(16));
    TokenStore::create();
    return true;
}

function viewer_do_logout(): void
{
    TokenStore::revoke();
    session_destroy();
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
    }
    return $_SESSION['csrf_token'];
}

function csrf_valid(string $token): bool
{
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// ---------------------------------------------------------------------------
// Content parsers
// ---------------------------------------------------------------------------

function parse_messages_field(?string $json): array
{
    if (!$json) return [];
    $decoded = json_decode($json, true);
    if (!is_array($decoded)) return [];
    return $decoded['messages'] ?? (isset($decoded[0]) ? $decoded : []);
}

function parse_completion_field(?string $json): array
{
    if (!$json) return [];
    $decoded = json_decode($json, true) ?? [];
    return [
        'completion' => $decoded['completion'] ?? null,
        'reasoning'  => $decoded['reasoning']  ?? null,
        'tools'      => $decoded['tools']       ?? [],
    ];
}

function ensure_utf8(?string $text): string
{
    if (!is_string($text) || $text === '') {
        return '';
    }
    if (preg_match('//u', $text) === 1) {
        return $text;
    }
    if (function_exists('iconv')) {
        $clean = iconv('UTF-8', 'UTF-8//IGNORE', $text);
        if (is_string($clean)) {
            return $clean;
        }
    }
    return '';
}

function safe_preg_replace(string $pattern, string $replacement, ?string $subject): string
{
    $subject = ensure_utf8($subject);
    if ($subject === '') {
        return '';
    }
    $result = preg_replace($pattern, $replacement, $subject);
    return is_string($result) ? $result : $subject;
}

function safe_datetime_format(?string $value, string $format = 'Y-m-d H:i:s'): string
{
    if (!is_string($value) || trim($value) === '') {
        return '';
    }
    try {
        return (new DateTime($value))->format($format);
    } catch (Throwable $e) {
        return '';
    }
}

function enrich_span(array $s): array
{
    $s['request_model_short']  = shorten_model($s['request_model'] ?? '');
    $s['response_model_short'] = shorten_model($s['response_model'] ?? '');
    $s['started_at_fmt'] = safe_datetime_format($s['started_at'] ?? null);
    $raw = ensure_utf8(
        first_user_message_preview($s['gen_ai_prompt'] ?? null)
        ?: first_user_message_preview($s['span_input'] ?? null)
    );
    $cleaned = safe_preg_replace(
        '/(\[cron:)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} /i',
        '$1',
        $raw
    );
    if (preg_match('/^\[cron:([^\]]+)\]/', $cleaned, $m)) {
        $s['cron_name']      = trim($m[1]);
        $s['heartbeat']      = false;
        $s['prompt_preview'] = '';
    } elseif (str_starts_with($cleaned, 'Read HEARTBEAT.md if it exists')) {
        $s['cron_name']      = null;
        $s['heartbeat']      = true;
        $s['prompt_preview'] = '';
    } else {
        $s['cron_name']      = null;
        $s['heartbeat']      = false;
        $s['prompt_preview'] = $cleaned;
    }
    $s['response_preview'] = completion_preview($s['gen_ai_completion'] ?? null)
        ?: completion_preview($s['span_output'] ?? null);
    unset($s['gen_ai_prompt'], $s['span_input'], $s['gen_ai_completion'], $s['span_output']);
    return $s;
}

function span_visible_for_hide(array $s, array $hide): bool
{
    if (in_array('cron', $hide, true) && isset($s['cron_name']) && $s['cron_name'] !== null) {
        return false;
    }
    if (in_array('heartbeat', $hide, true) && !empty($s['heartbeat'])) {
        return false;
    }
    if (in_array('other', $hide, true) && $s['cron_name'] === null && empty($s['heartbeat'])) {
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// DB query functions
// ---------------------------------------------------------------------------

$ALLOWED_SORT_COLS = [
    'started_at', 'trace_name', 'request_model', 'response_model',
    'duration_ms', 'input_tokens', 'output_tokens', 'cached_tokens',
    'total_cost_usd', 'finish_reason', 'received_at',
];

function build_where(array $opts): array
{
    $conditions = [];
    $params     = [];

    if (!empty($opts['search'])) {
        $like = '%' . $opts['search'] . '%';
        $cols = ['trace_name','request_model','response_model','provider_name',
                 'finish_reason','operation_name','api_key_name','user_id',
                 'entity_id','trace_id','span_id'];
        $conditions[] = '(' . implode(' OR ', array_map(fn($c) => "$c LIKE ?", $cols)) . ')';
        $params = array_merge($params, array_fill(0, count($cols), $like));
    }

    // NOTE: hide-type filtering is done in PHP after type detection,
    // not in SQL — SQL LIKE on the raw JSON blob is too broad and matches
    // e.g. system prompts that mention "Read HEARTBEAT.md" as an instruction.
    $where = $conditions ? 'WHERE ' . implode(' AND ', $conditions) : '';
    return [$where, $params];
}

function db_get_spans(PDO $pdo, array $opts): array
{
    global $ALLOWED_SORT_COLS;
    $col    = in_array($opts['sort'] ?? '', $ALLOWED_SORT_COLS, true) ? $opts['sort'] : 'started_at';
    $dir    = ($opts['dir'] ?? 'DESC') === 'ASC' ? 'ASC' : 'DESC';
    $page   = max(1, (int)($opts['page'] ?? 1));
    $per    = max(1, (int)($opts['per'] ?? 50));
    $offset = isset($opts['offset']) ? max(0, (int)$opts['offset']) : (($page - 1) * $per);

    [$where, $params] = build_where($opts);

    $limit_clause = "LIMIT $per OFFSET $offset";
    $sql = "SELECT id, started_at, request_model, response_model,
                   duration_ms, input_tokens, output_tokens, cached_tokens,
                   total_cost_usd, finish_reason, finish_reasons, span_type,
                   operation_name, trace_id, span_id,
                   gen_ai_prompt, span_input, gen_ai_completion, span_output
            FROM traces
            $where
            ORDER BY $col $dir
            $limit_clause";

    $stmt = $pdo->prepare($sql);
    $stmt->execute($params);
    return $stmt->fetchAll();
}

function db_count_spans(PDO $pdo, array $opts): int
{
    [$where, $params] = build_where($opts);
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM traces $where");
    $stmt->execute($params);
    return (int)$stmt->fetchColumn();
}

function db_get_stats(PDO $pdo): array
{
    $stmt = $pdo->query(
        "SELECT COUNT(*) AS total_spans,
                COALESCE(SUM(total_cost_usd), 0) AS total_cost,
                COALESCE(AVG(duration_ms), 0) AS avg_duration_ms,
                COALESCE(SUM(input_tokens + output_tokens), 0) AS total_tokens
         FROM traces"
    );
    return $stmt->fetch();
}

function db_get_detail(PDO $pdo, int $id): ?array
{
    $stmt = $pdo->prepare(
        "SELECT id, trace_id, span_id, openrouter_trace_id,
                request_model, response_model, provider_name, provider_slug,
                operation_name, span_type, finish_reason, finish_reasons, trace_name,
                input_tokens, output_tokens, cached_tokens, reasoning_tokens,
                audio_tokens, video_tokens, image_tokens,
                input_cost_usd, output_cost_usd, total_cost_usd,
                input_unit_price, output_unit_price,
                started_at, ended_at, duration_ms,
                span_input, span_output, trace_input, trace_output,
                gen_ai_prompt, gen_ai_completion,
                api_key_name, user_id, entity_id, received_at
         FROM traces WHERE id = :id LIMIT 1"
    );
    $stmt->execute([':id' => $id]);
    return $stmt->fetch() ?: null;
}

// ---------------------------------------------------------------------------
// JSON response helper
// ---------------------------------------------------------------------------

function json_out(array $data, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

// ---------------------------------------------------------------------------
// Action handlers
// ---------------------------------------------------------------------------

function action_spans(PDO $pdo): void
{
    $opts = [
        'sort'   => $_GET['sort']   ?? 'started_at',
        'dir'    => $_GET['dir']    ?? 'DESC',
        'page'   => $_GET['page']   ?? 1,
        'search' => $_GET['search'] ?? '',
        'hide'   => $_GET['hide']   ?? '',
    ];
    $hide = array_filter(explode(',', $opts['hide']));
    $per  = 50;
    $page = max(1, (int)($opts['page'] ?? 1));
    $scanOffset = max(0, (int)($_GET['scan_offset'] ?? 0));

    try {
        if ($hide) {
            $batchSize = 100;
            $spans     = [];
            $offset    = $scanOffset;
            $lastCount = 0;

            while (count($spans) < $per) {
                $batch = db_get_spans($pdo, $opts + [
                    'per'    => $batchSize,
                    'offset' => $offset,
                ]);
                $lastCount = count($batch);
                foreach ($batch as $row) {
                    $row = enrich_span($row);
                    if (!span_visible_for_hide($row, $hide)) {
                        continue;
                    }
                    $spans[] = $row;
                    if (count($spans) >= $per) {
                        break;
                    }
                }
                unset($batch); // free raw JSON blobs before next iteration
                $offset += $lastCount;
                if ($lastCount < $batchSize) {
                    break; // no more records in DB
                }
            }

            $hasMore = ($lastCount === $batchSize && count($spans) >= $per);
            json_out([
                'spans'       => $spans,
                'total'       => null,
                'page'        => 1,
                'filtered'    => true,
                'next_offset' => $offset,
                'has_more'    => $hasMore,
            ]);
        } else {
            $spans = array_map('enrich_span', db_get_spans($pdo, $opts));
            $total = db_count_spans($pdo, $opts);
            json_out(['spans' => $spans, 'total' => $total, 'page' => $page, 'filtered' => false]);
        }
    } catch (Throwable $e) {
        json_out([
            'error' => 'Exception in action_spans',
            'debug' => [
                'message' => $e->getMessage(),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
                'trace' => $e->getTraceAsString(),
            ],
            'opts' => $opts,
        ], 500);
    }
}

function action_detail(PDO $pdo): void
{
    $id = (int)($_GET['id'] ?? 0);
    if ($id <= 0) {
        json_out(['error' => 'Invalid id'], 400);
    }

    $row = db_get_detail($pdo, $id);
    if (!$row) {
        json_out(['error' => 'Not found'], 404);
    }

    // Extract large text fields, parse them, then remove raw from scalar list
    $gen_ai_prompt      = $row['gen_ai_prompt']      ?? null;
    $gen_ai_completion  = $row['gen_ai_completion']  ?? null;
    $span_input         = $row['span_input']         ?? null;
    $span_output        = $row['span_output']        ?? null;
    $trace_input        = $row['trace_input']        ?? null;
    $trace_output       = $row['trace_output']       ?? null;

    $text_fields = ['gen_ai_prompt','gen_ai_completion','span_input','span_output','trace_input','trace_output'];
    $scalars = array_diff_key($row, array_flip($text_fields));

    json_out([
        'span'                     => $scalars,
        'gen_ai_messages'          => parse_messages_field($gen_ai_prompt),
        'gen_ai_completion_parsed' => parse_completion_field($gen_ai_completion),
        'span_messages'            => parse_messages_field($span_input),
        'span_output_parsed'       => parse_completion_field($span_output),
        'trace_input_raw'          => $trace_input,
        'trace_output_raw'         => $trace_output,
    ]);
}

function action_stats(PDO $pdo): void
{
    $stats = db_get_stats($pdo);
    json_out($stats);
}

function first_user_message_preview(?string $json, int $len = 100): string
{
    if (!$json) return '';
    $decoded = json_decode($json, true);
    if (!is_array($decoded)) return '';
    $messages = $decoded['messages'] ?? (isset($decoded[0]) ? $decoded : []);
    $last = '';
    foreach ($messages as $msg) {
        if (($msg['role'] ?? '') !== 'user') continue;
        $content = $msg['content'] ?? '';
        $text = '';
        if (is_string($content)) {
            $text = $content;
        } elseif (is_array($content)) {
            foreach ($content as $part) {
                if (is_string($part)) { $text = $part; break; }
                if (($part['type'] ?? '') === 'text') { $text = $part['text'] ?? ''; break; }
            }
        }
        if ($text === '') continue;
        $text = ensure_utf8($text);
        if ($text === '') continue;
        if (str_starts_with($text, 'A new session was started')) continue;
        // Strip "X (untrusted metadata):\n```json\n...\n```\n" blocks (multiline)
        $text = safe_preg_replace('/\S[^\n]*\(untrusted metadata\):\s*\n```json\n.*?```\s*\n*/si', '', $text);
        // Strip any remaining single-line "X (untrusted metadata):" prefixes
        $text = safe_preg_replace('/\S[^\n]*\(untrusted metadata\):?\s*/i', '', $text);
        // Strip entire "System: [timestamp] ..." lines
        $text = safe_preg_replace('/^System:\s*\[.*?\][^\n]*\n*/mi', '', $text);
        $text = trim($text);
        if ($text !== '') $last = $text;
    }
    return mb_substr(ensure_utf8($last), 0, $len);
}

function completion_preview(?string $json, int $len = 100): string
{
    if (!$json) return '';
    $decoded = json_decode($json, true);
    if (!is_array($decoded)) return '';
    $text = $decoded['completion'] ?? null;
    if ($text === null) return '';
    if (is_string($text)) return mb_substr(trim(ensure_utf8($text)), 0, $len);
    if (is_array($text)) {
        foreach ($text as $part) {
            if (is_string($part)) return mb_substr(trim(ensure_utf8($part)), 0, $len);
            if (($part['type'] ?? '') === 'text') return mb_substr(trim(ensure_utf8($part['text'] ?? '')), 0, $len);
        }
    }
    return '';
}

function shorten_model(string $model): string
{
    // Strip provider prefix like "openai/" or "anthropic/"
    if (str_contains($model, '/')) {
        $parts = explode('/', $model);
        return end($parts);
    }
    return $model;
}

// ---------------------------------------------------------------------------
// Security headers (applied to all responses)
// ---------------------------------------------------------------------------

header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' http://127.0.0.1:* http://localhost:*");
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');

// ---------------------------------------------------------------------------
// Request routing
// ---------------------------------------------------------------------------

// API actions — require auth
if (isset($_GET['_action'])) {
    if (!viewer_check_auth()) {
        json_out(['error' => 'Unauthorized'], 401);
    }
    try {
        $db  = new Database($config['db']);
        $pdo = $db->getConnection();
    } catch (Exception $e) {
        json_out(['error' => 'Database error'], 500);
    }

    $action = $_GET['_action'];
    if ($action === 'spans')  action_spans($pdo);
    if ($action === 'detail') action_detail($pdo);
    if ($action === 'stats')  action_stats($pdo);
    json_out(['error' => 'Unknown action'], 400);
}

// Login POST
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['_viewer_action'])) {
    $va = $_POST['_viewer_action'];

    if ($va === 'login') {
        $password = $_POST['password'] ?? '';
        $csrf     = $_POST['csrf']     ?? '';
        // For login, generate token if not yet set
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
        }
        if (!csrf_valid($csrf)) {
            $loginError = 'Invalid request. Please try again.';
        } elseif (viewer_do_login($password, $config)) {
            header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
            exit;
        } else {
            $loginError = 'Incorrect password.';
        }
    } elseif ($va === 'logout') {
        if (csrf_valid($_POST['csrf'] ?? '')) {
            viewer_do_logout();
        }
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    } elseif ($va === 'cleanup') {
        if (!viewer_check_auth()) { http_response_code(403); exit; }
        if (!csrf_valid($_POST['csrf'] ?? '')) { http_response_code(403); exit; }
        $pdo = (new Database($config['db']))->getConnection();
        $tracesDeleted = 0;
        $authDeleted   = 0;
        try {
            $stmt = $pdo->prepare('DELETE FROM traces WHERE received_at < DATE_SUB(NOW(), INTERVAL 3 DAY)');
            $stmt->execute();
            $tracesDeleted = $stmt->rowCount();
            $stmt = $pdo->prepare('DELETE FROM auth_failures WHERE failed_at < DATE_SUB(NOW(), INTERVAL 3 DAY)');
            $stmt->execute();
            $authDeleted = $stmt->rowCount();
            $_SESSION['flash'] = ($tracesDeleted + $authDeleted > 0)
                ? "Deleted {$tracesDeleted} traces and {$authDeleted} auth failures."
                : 'No entries older than 3 days found.';
        } catch (Exception $e) {
            $_SESSION['flash'] = 'Cleanup failed. Please try again.';
        }
        header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
        exit;
    }
}

// Ensure CSRF token exists for login form
csrf_token();

$isAuthed = viewer_check_auth();
$isMockMode = $VIEWER_API_BASE !== '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OpenRouter Trace Dashboard</title>
<style>
:root {
    --bg: #fff;
    --surface: #f8f9fa;
    --surface2: #f1f3f5;
    --border: #e0e3e8;
    --text: #1a1d23;
    --muted: #6b7280;
    --accent: #2563eb;
    --accent-hover: #1d4ed8;
    --green: #16a34a;
    --amber: #d97706;
    --red: #dc2626;
    --panel-w: 520px;
    --header-h: 52px;
}
*, *::before, *::after { box-sizing: border-box; }
body {
    margin: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    font-size: 14px;
    background: var(--bg);
    color: var(--text);
    display: flex;
    flex-direction: column;
    height: 100dvh;
    overflow: hidden;
}

/* ---------- Header ---------- */
header {
    background: var(--text);
    color: #fff;
    padding: 0 20px;
    min-height: var(--header-h);
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-shrink: 0;
}
.header-left {
    display: flex;
    align-items: center;
    gap: 10px;
}
header h1 { font-size: 16px; font-weight: 600; margin: 0; letter-spacing: 0.01em; }
header .header-right { display: flex; align-items: center; gap: 12px; }
.mode-badge {
    display: inline-flex;
    align-items: center;
    border: 1px solid rgba(255,255,255,0.25);
    background: rgba(255,255,255,0.08);
    color: rgba(255,255,255,0.92);
    border-radius: 999px;
    padding: 4px 10px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}
.header-btn {
    background: transparent;
    border: 1px solid rgba(255,255,255,0.3);
    color: #fff;
    padding: 5px 12px;
    border-radius: 5px;
    cursor: pointer;
    font-size: 13px;
    transition: background 0.12s, opacity 0.12s;
}
.header-btn:hover:not(:disabled) { background: rgba(255,255,255,0.1); }
.header-btn:disabled { opacity: 0.65; cursor: wait; }
.btn-refresh {
    width: 34px;
    height: 34px;
    padding: 0;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    position: relative;
}
.btn-refresh svg {
    width: 19px;
    height: 19px;
    display: block;
    fill: currentColor;
}
.btn-refresh.is-loading::before {
    content: '';
    display: block;
    width: 11px;
    height: 11px;
    border: 2px solid rgba(255,255,255,0.35);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
    position: absolute;
    inset: 0;
    margin: auto;
}
.btn-refresh.is-loading {
    color: transparent;
}
.btn-refresh.is-loading svg {
    opacity: 0;
}
.burger-menu {
    position: relative;
}
.burger-dropdown {
    position: absolute;
    top: calc(100% + 8px);
    right: 0;
    background: #fff;
    border: 1px solid var(--border);
    border-radius: 7px;
    box-shadow: 0 4px 16px rgba(0,0,0,0.14);
    min-width: 170px;
    z-index: 200;
    padding: 4px 0;
}
.burger-item {
    display: block;
    width: 100%;
    background: none;
    border: none;
    padding: 9px 16px;
    text-align: left;
    font-size: 13px;
    color: var(--text);
    cursor: pointer;
    border-radius: 0;
}
.burger-divider {
    margin: 4px 0;
    border-top: 1px solid var(--border);
}
.burger-item:hover { background: var(--row-hover); }
.flash-msg {
    margin: 10px 20px 0;
    padding: 9px 14px;
    border-radius: 6px;
    font-size: 13px;
    background: #ecfdf5;
    border: 1px solid #6ee7b7;
    color: #065f46;
}

/* ---------- Stats footer ---------- */
#stats-footer {
    display: flex;
    gap: 8px;
    padding: 4px 20px;
    background: #fbfcfd;
    border-top: 1px solid var(--border);
    flex-shrink: 0;
    align-items: center;
    overflow-x: auto;
}
.stat-card {
    background: transparent;
    border: 1px solid rgba(224,227,232,0.55);
    border-radius: 999px;
    padding: 2px 7px;
    min-width: 0;
    display: inline-flex;
    align-items: baseline;
    gap: 5px;
    white-space: nowrap;
}
.stat-card .label { font-size: 8px; color: #8a94a6; text-transform: uppercase; letter-spacing: 0.04em; line-height: 1; }
.stat-card .value { font-size: 11px; font-weight: 500; color: #4b5563; line-height: 1.1; }

/* ---------- Toolbar ---------- */
#toolbar {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 20px;
    border-bottom: 1px solid var(--border);
    background: var(--bg);
    flex-shrink: 0;
}
#toolbar input[type=text] {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 13px;
    width: 220px;
    outline: none;
}
#toolbar input[type=text]:focus { border-color: var(--accent); }
.hide-label { font-size: 12px; color: var(--muted); white-space: nowrap; }
.hide-toggle {
    border: 1px solid var(--border);
    background: var(--bg);
    color: var(--muted);
    padding: 4px 9px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.12s, color 0.12s, border-color 0.12s;
}
.hide-toggle:hover { border-color: var(--text); color: var(--text); }
.hide-toggle.active { background: var(--text); color: #fff; border-color: var(--text); }
.clear-filters {
    border: none;
    background: none;
    color: var(--muted);
    padding: 0;
    font-size: 12px;
    cursor: pointer;
    white-space: nowrap;
    text-decoration: underline;
    text-underline-offset: 2px;
}
.clear-filters:hover { color: var(--text); }
.clear-filters:disabled {
    color: #b7bfcb;
    cursor: default;
    text-decoration: none;
    opacity: 0.7;
}

/* ---------- Main layout ---------- */
#main-area {
    display: flex;
    flex: 1;
    overflow: hidden;
    position: relative;
    min-height: 0;
}

/* ---------- Table area ---------- */
#table-area {
    flex: 1;
    overflow-y: auto;
    overflow-x: auto;
    transition: margin-right 0.25s ease;
}
#table-area.panel-open { margin-right: var(--panel-w); }

table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}
thead th {
    background: var(--surface);
    border-bottom: 2px solid var(--border);
    padding: 8px 10px;
    text-align: left;
    white-space: nowrap;
    position: sticky;
    top: 0;
    z-index: 2;
    font-weight: 600;
    font-size: 12px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
    cursor: pointer;
    user-select: none;
}
thead th:hover { color: var(--text); }
thead th.sort-asc::after  { content: ' ▲'; color: var(--accent); }
thead th.sort-desc::after { content: ' ▼'; color: var(--accent); }
tbody tr {
    border-bottom: 1px solid var(--border);
    cursor: pointer;
    transition: background 0.1s;
}
tbody tr:hover { background: var(--surface); }
tbody tr.active { background: #eff6ff; }
tbody td { padding: 7px 10px; vertical-align: middle; }
.td-right { text-align: right; }
.td-mono  { font-family: 'SF Mono', 'Fira Code', monospace; font-size: 12px; }
.td-preview { color: var(--muted); font-style: italic; }

/* Duration color coding */
.dur-green { color: var(--green); font-weight: 500; }
.dur-amber { color: var(--amber); font-weight: 500; }
.dur-red   { color: var(--red);   font-weight: 500; }

/* Finish reason badge */
.badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 500;
    background: var(--surface2);
    color: var(--muted);
    text-transform: lowercase;
}
.badge-stop   { background: #dcfce7; color: #166534; }
.badge-length { background: #fef9c3; color: #854d0e; }
.badge-error  { background: #fee2e2; color: #991b1b; }
.badge-cron      { background: #fef08a; color: #713f12; cursor: default; border-radius: 3px; }
.badge-heartbeat  { background: #fce7f3; color: #9d174d; cursor: default; border-radius: 3px; }


/* ---------- Pagination ---------- */
#pagination {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    padding: 14px 20px;
    border-top: 1px solid var(--border);
    background: var(--bg);
    flex-shrink: 0;
    flex-wrap: wrap;
}
.page-btn {
    border: 1px solid var(--border);
    background: var(--bg);
    color: var(--text);
    padding: 4px 9px;
    border-radius: 999px;
    cursor: pointer;
    font-size: 12px;
    min-width: 34px;
}
.page-btn:hover:not(:disabled) { background: var(--surface); }
.page-btn:disabled { opacity: 0.4; cursor: default; }
.page-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
.page-ellipsis {
    color: var(--muted);
    font-size: 12px;
    padding: 0 2px;
    user-select: none;
}

/* ---------- Detail panel ---------- */
#detail-panel {
    position: fixed;
    top: var(--header-h);
    right: 0;
    width: var(--panel-w);
    bottom: 0;
    background: var(--bg);
    border-left: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    transform: translateX(100%);
    transition: transform 0.25s ease;
    z-index: 100;
    box-shadow: -4px 0 20px rgba(0,0,0,0.08);
}
#detail-panel.open { transform: translateX(0); }
#detail-backdrop {
    position: fixed;
    inset: var(--header-h) 0 0 0;
    background: rgba(15, 23, 42, 0.22);
    opacity: 0;
    pointer-events: none;
    transition: opacity 0.2s ease;
    z-index: 90;
}
#detail-backdrop.open {
    opacity: 0;
}
#table-area.page-loading {
    position: relative;
}
#table-area.page-loading::after {
    content: '';
    position: absolute;
    inset: 0;
    background: rgba(0, 0, 0, 0.18);
    z-index: 80;
    pointer-events: auto;
}
#detail-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
}
#detail-header h2 { margin: 0; font-size: 14px; font-weight: 600; }
#detail-close {
    background: none;
    border: none;
    cursor: pointer;
    font-size: 20px;
    line-height: 1;
    color: var(--muted);
    padding: 2px 6px;
}
#detail-close:hover { color: var(--text); }
#detail-tabs {
    display: flex;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
    background: var(--surface);
}
.tab-btn {
    flex: 1;
    padding: 9px 8px;
    border: none;
    background: none;
    cursor: pointer;
    font-size: 12px;
    font-weight: 500;
    color: var(--muted);
    border-bottom: 2px solid transparent;
    transition: color 0.15s;
}
.tab-btn:hover { color: var(--text); }
.tab-btn.active { color: var(--accent); border-bottom-color: var(--accent); }
#detail-body {
    flex: 1;
    overflow-y: auto;
    padding: 16px;
}

/* Detail meta grid */
.meta-grid {
    display: grid;
    grid-template-columns: 140px 1fr;
    gap: 2px 8px;
    font-size: 12px;
    margin-bottom: 16px;
}
.meta-key   { color: var(--muted); padding: 3px 0; word-break: break-word; }
.meta-val   { padding: 3px 0; word-break: break-all; font-family: 'SF Mono', monospace; font-size: 11px; }

/* Message nav arrows */
#msg-nav {
    position: absolute;
    right: 12px;
    top: 50%;
    transform: translateY(-50%);
    display: flex;
    flex-direction: column;
    gap: 6px;
    z-index: 20;
    opacity: 0.25;
}
#msg-nav.hidden { display: none; }
#msg-nav:hover { opacity: 0.85; }
#msg-nav button {
    width: 32px; height: 32px;
    border-radius: 50%;
    border: 1px solid var(--border);
    background: var(--bg);
    box-shadow: 0 2px 8px rgba(0,0,0,0.10);
    cursor: pointer;
    font-size: 15px;
    line-height: 1;
    display: flex; align-items: center; justify-content: center;
    transition: background 0.12s;
}
#msg-nav button:hover:not(:disabled) { background: var(--surface2); }
#msg-nav button:disabled { opacity: 0.25; cursor: default; box-shadow: none; }
#msg-nav button.nav-edge { flex-direction: column; gap: 2px; }
#msg-nav .nav-bar { display: block; width: 14px; height: 2px; background: currentColor; border-radius: 1px; }

/* Chat bubbles */
.chat-wrap { display: flex; flex-direction: column; gap: 10px; }
.msg-bubble {
    max-width: 90%;
    padding: 10px 13px;
    border-radius: 10px;
    font-size: 13px;
    line-height: 1.5;
    white-space: pre-wrap;
    word-break: break-word;
}
.msg-system {
    border-left: 3px solid #93c5fd;
    background: #eff6ff;
    color: #1e3a5f;
    align-self: flex-start;
    max-width: 100%;
    border-radius: 4px;
}
.msg-user {
    background: #dbeafe;
    color: #1e40af;
    align-self: flex-end;
    border-radius: 10px 10px 2px 10px;
}
.msg-assistant {
    background: var(--surface2);
    color: var(--text);
    align-self: flex-start;
    border-radius: 10px 10px 10px 2px;
}
.msg-tool {
    border: 1px solid #fde68a;
    background: #fffbeb;
    color: #78350f;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 12px;
    align-self: flex-start;
    max-width: 100%;
    border-radius: 4px;
}
.msg-role-label {
    font-size: 10px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin-bottom: 4px;
    border-radius: 6px;
    transition: color 0.18s ease, background 0.18s ease, box-shadow 0.18s ease;
}
.msg-role-label.is-flashing {
    animation: msg-label-flash 0.8s ease;
}
@keyframes msg-label-flash {
    0% {
        color: var(--accent);
        background: rgba(37, 99, 235, 0.16);
        box-shadow: 0 0 0 0 rgba(37, 99, 235, 0.22);
    }
    45% {
        color: var(--accent);
        background: rgba(37, 99, 235, 0.22);
        box-shadow: 0 0 0 6px rgba(37, 99, 235, 0.08);
    }
    100% {
        color: var(--muted);
        background: transparent;
        box-shadow: 0 0 0 0 rgba(37, 99, 235, 0);
    }
}
.detail-section-title {
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--muted);
    margin: 16px 0 8px;
    padding-bottom: 4px;
    border-bottom: 1px solid var(--border);
}
details.collapsible {
    border: 1px solid var(--border);
    border-radius: 6px;
    margin-top: 8px;
}
details.collapsible summary {
    padding: 8px 12px;
    cursor: pointer;
    font-size: 12px;
    font-weight: 600;
    color: var(--muted);
    user-select: none;
}
details.collapsible > .detail-content {
    padding: 10px 12px;
    font-family: 'SF Mono', monospace;
    font-size: 12px;
    white-space: pre-wrap;
    word-break: break-all;
    border-top: 1px solid var(--border);
    max-height: 300px;
    overflow-y: auto;
}
.json-view {
    margin: 0;
    white-space: pre-wrap;
    word-break: break-word;
    color: #0f172a;
}
.json-key { color: #9f1239; }
.json-string { color: #166534; }
.json-number { color: #1d4ed8; }
.json-boolean { color: #7c3aed; font-weight: 600; }
.json-null { color: #b45309; font-style: italic; }

/* ---------- Login form ---------- */
.login-wrap {
    display: flex;
    align-items: center;
    justify-content: center;
    flex: 1;
    background: var(--surface);
}
.login-card {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 36px 40px;
    width: 360px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.06);
}
.login-card h2 {
    margin: 0 0 24px;
    font-size: 20px;
    font-weight: 700;
    text-align: center;
}
.login-card label {
    display: block;
    font-size: 13px;
    font-weight: 500;
    margin-bottom: 6px;
    color: var(--muted);
}
.login-card input[type=password] {
    width: 100%;
    border: 1px solid var(--border);
    border-radius: 7px;
    padding: 9px 12px;
    font-size: 14px;
    outline: none;
    transition: border-color 0.15s;
}
.login-card input[type=password]:focus { border-color: var(--accent); }
.login-card .btn-primary {
    width: 100%;
    margin-top: 16px;
    padding: 10px;
    background: var(--accent);
    color: #fff;
    border: none;
    border-radius: 7px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s;
}
.login-card .btn-primary:hover { background: var(--accent-hover); }
.login-error {
    margin-top: 12px;
    padding: 9px 12px;
    background: #fee2e2;
    color: #991b1b;
    border-radius: 6px;
    font-size: 13px;
}

/* ---------- Loading / empty states ---------- */
.state-row td { text-align: center; padding: 40px; color: var(--muted); font-size: 14px; }
.spinner {
    display: inline-block;
    width: 18px; height: 18px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
    vertical-align: middle;
    margin-right: 8px;
}
@keyframes spin { to { transform: rotate(360deg); } }

@media (max-width: 860px) {
    :root {
        --panel-w: 100vw;
        --header-h: 82px;
    }

    body {
        overflow: auto;
    }

    header {
        height: auto;
        align-items: flex-start;
        gap: 8px;
        padding: 10px 12px;
        flex-wrap: wrap;
    }

    header h1 {
        font-size: 15px;
    }

    header h1 {
        width: auto;
    }

    .header-left,
    header .header-right {
        width: 100%;
        justify-content: space-between;
        gap: 6px;
        flex-wrap: wrap;
    }

    .header-btn,
    .mode-badge,
    .header-left,
    header .header-right form {
        flex: 1 1 auto;
    }

    .btn-refresh {
        flex: 0 0 auto;
    }

    header .header-right form button {
        width: 100%;
    }

    #toolbar {
        padding: 8px 12px;
        display: grid;
        grid-template-columns: minmax(0, 1fr) auto auto auto auto;
        align-items: center;
        gap: 6px;
    }

    #toolbar input[type=text] {
        width: 100%;
        min-width: 0;
        padding: 5px 9px;
        font-size: 12px;
    }

    .hide-label,
    .hide-toggle,
    .clear-filters {
        font-size: 11px;
    }

    .hide-label {
        justify-self: end;
        white-space: nowrap;
    }

    .hide-toggle {
        padding: 4px 7px;
        white-space: nowrap;
    }

    #table-area {
        overflow-x: hidden;
    }

    #table-area.panel-open {
        margin-right: 0;
    }

    #spans-table,
    #spans-table tbody {
        display: block;
    }

    #spans-table thead {
        display: none;
    }

    #spans-table tbody tr[data-id] {
        display: grid;
        grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
        grid-template-areas:
            "started finish"
            "prompt prompt"
            "result result";
        margin: 6px 8px;
        border: 1px solid var(--border);
        border-radius: 10px;
        background: var(--bg);
        box-shadow: 0 4px 14px rgba(15, 23, 42, 0.04);
        overflow: hidden;
    }

    #spans-table tbody tr[data-id].active {
        background: #eff6ff;
        border-color: #bfdbfe;
    }

    #spans-table tbody td {
        display: block;
        padding: 7px 10px;
        border-top: 1px solid rgba(224,227,232,0.75);
        text-align: left;
        min-width: 0;
    }

    #spans-table tbody tr[data-id] td:first-child {
        border-top: none;
    }

    #spans-table tbody td::before {
        content: attr(data-label);
        display: block;
        margin-bottom: 2px;
        color: var(--muted);
        font-size: 10px;
        font-weight: 700;
        letter-spacing: 0.04em;
        text-transform: uppercase;
    }

    #spans-table tbody td.td-right {
        text-align: left;
    }

    #spans-table tbody td.td-preview {
        font-style: normal;
        line-height: 1.3;
    }

    #spans-table tbody tr[data-id] td:nth-child(1) {
        grid-area: started;
    }

    #spans-table tbody tr[data-id] td:nth-child(3) {
        grid-area: result;
        border-top: none;
    }

    #spans-table tbody tr[data-id] td:nth-child(2) {
        grid-area: prompt;
    }

    #spans-table tbody tr[data-id] td:nth-child(4) {
        grid-area: finish;
        border-top: none;
        border-left: 1px solid rgba(224,227,232,0.75);
    }

    #spans-table tbody tr[data-id] td:nth-child(1),
    #spans-table tbody tr[data-id] td:nth-child(4) {
        display: flex;
        align-items: baseline;
        gap: 6px;
    }

    #spans-table tbody tr[data-id] td:nth-child(1)::before,
    #spans-table tbody tr[data-id] td:nth-child(4)::before {
        margin-bottom: 0;
        flex: 0 0 auto;
        min-width: 38px;
    }

    #spans-table tbody tr[data-id] td:nth-child(n + 5) {
        display: none;
    }

    #spans-table .state-row {
        margin: 0;
        border: 0;
        box-shadow: none;
    }

    #spans-table .state-row td {
        display: table-cell;
        border-top: none;
        text-align: center;
    }

    #spans-table .state-row td::before {
        display: none;
    }

    #detail-backdrop {
        inset: 0;
    }

    #detail-panel {
        top: 0;
        width: 100vw;
        height: 100dvh;
        bottom: auto;
        border-left: none;
        box-shadow: none;
    }

    #detail-header {
        padding: 10px 12px;
    }

    #detail-header h2 {
        max-width: calc(100% - 44px);
    }

    #detail-tabs {
        overflow-x: auto;
    }

    .tab-btn {
        flex: 0 0 auto;
        min-width: 88px;
        padding: 8px 6px;
        font-size: 11px;
    }

    #detail-body {
        padding: 14px;
        padding-bottom: calc(14px + env(safe-area-inset-bottom, 0px));
    }

    .meta-grid {
        grid-template-columns: 1fr;
        gap: 0;
    }

    .meta-key {
        padding-top: 10px;
        font-weight: 700;
    }

    .meta-val {
        padding-bottom: 10px;
        word-break: break-word;
    }

    .msg-bubble {
        max-width: 100%;
    }

    #msg-nav {
        right: 8px;
        bottom: 12px;
        top: auto;
        transform: none;
        opacity: 0.9;
    }

    #stats-footer {
        padding: 8px 12px calc(8px + env(safe-area-inset-bottom, 0px));
        gap: 6px;
        scroll-padding: 12px;
    }
}
</style>
</head>
<body>

<?php if (!$isAuthed): ?>
<!-- ====================================================================== -->
<!-- LOGIN FORM                                                              -->
<!-- ====================================================================== -->
<header>
    <h1>OpenRouter Trace Dashboard</h1>
</header>
<div class="login-wrap">
    <div class="login-card">
        <h2>Sign in</h2>
        <form method="POST">
            <input type="hidden" name="_viewer_action" value="login">
            <input type="hidden" name="csrf" value="<?= htmlspecialchars(csrf_token()) ?>">
            <label for="password">Password</label>
            <input type="password" id="password" name="password" autofocus autocomplete="current-password" required>
            <button type="submit" class="btn-primary">Unlock Dashboard</button>
            <?php if (!empty($loginError)): ?>
            <div class="login-error"><?= htmlspecialchars($loginError) ?></div>
            <?php endif; ?>
        </form>
    </div>
</div>

<?php else: ?>
<!-- ====================================================================== -->
<!-- AUTHENTICATED DASHBOARD                                                 -->
<!-- ====================================================================== -->
<header>
    <div class="header-left">
        <h1>OpenRouter Trace Dashboard</h1>
        <button type="button" class="header-btn btn-refresh" id="refresh-dashboard" title="Refresh" aria-label="Refresh">
            <svg id="Layer_1" data-name="Layer 1" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 118.04 122.88" aria-hidden="true" focusable="false">
                <path d="M16.08,59.26A8,8,0,0,1,0,59.26a59,59,0,0,1,97.13-45V8a8,8,0,1,1,16.08,0V33.35a8,8,0,0,1-8,8L80.82,43.62a8,8,0,1,1-1.44-15.95l8-.73A43,43,0,0,0,16.08,59.26Zm22.77,19.6a8,8,0,0,1,1.44,16l-10.08.91A42.95,42.95,0,0,0,102,63.86a8,8,0,0,1,16.08,0A59,59,0,0,1,22.3,110v4.18a8,8,0,0,1-16.08,0V89.14h0a8,8,0,0,1,7.29-8l25.31-2.3Z"/>
            </svg>
        </button>
    </div>
    <div class="header-right">
        <?php if ($isMockMode): ?>
        <span class="mode-badge">Mock API</span>
        <?php endif; ?>
        <div class="burger-menu" id="burger-menu">
            <button type="button" class="header-btn" id="burger-toggle" aria-label="Menu">&#9776;</button>
            <div class="burger-dropdown" id="burger-dropdown" hidden>
                <form method="POST" style="margin:0">
                    <input type="hidden" name="_viewer_action" value="cleanup">
                    <input type="hidden" name="csrf" value="<?= htmlspecialchars(csrf_token()) ?>">
                    <button type="submit" class="burger-item" onclick="return confirm('Delete all entries older than 3 days? This action cannot be undone.')">
                        Cleanup Database...
                    </button>
                </form>
                <div class="burger-divider" role="separator" aria-hidden="true"></div>
                <form method="POST" style="margin:0">
                    <input type="hidden" name="_viewer_action" value="logout">
                    <input type="hidden" name="csrf" value="<?= htmlspecialchars(csrf_token()) ?>">
                    <button type="submit" class="burger-item">Sign out</button>
                </form>
            </div>
        </div>
    </div>
</header>

<?php if (!empty($_SESSION['flash'])): ?>
<div class="flash-msg"><?= htmlspecialchars($_SESSION['flash']) ?></div>
<?php unset($_SESSION['flash']); endif; ?>

<div id="toolbar">
    <input type="text" id="search-filter" placeholder="Search…" autocomplete="off">
    <span class="hide-label">Hide:</span>
    <button class="hide-toggle" data-type="cron">Cron</button>
    <button class="hide-toggle" data-type="heartbeat">Heartbeat</button>
    <button class="hide-toggle" data-type="other">Other</button>
    <button type="button" class="clear-filters" id="clear-filters">Clear filters</button>
</div>

<div id="main-area">
    <div id="table-area">
        <table id="spans-table">
            <thead>
                <tr>
                    <th data-col="started_at"    class="sort-desc">Started</th>
                    <th>Prompt</th>
                    <th>Result</th>
                    <th data-col="finish_reason">Finish</th>
                    <th data-col="duration_ms">Duration</th>
                    <th data-col="request_model">Req Model</th>
                    <th data-col="response_model">Resp Model</th>
                    <th data-col="input_tokens"  class="td-right">In Tok</th>
                    <th data-col="output_tokens" class="td-right">Out Tok</th>
                    <th data-col="cached_tokens" class="td-right">Cache</th>
                    <th data-col="total_cost_usd" class="td-right">Cost</th>
                </tr>
            </thead>
            <tbody id="spans-body">
                <tr class="state-row"><td colspan="11"><span class="spinner"></span>Loading…</td></tr>
            </tbody>
        </table>
        <div id="pagination"></div>
    </div>

    <div id="detail-backdrop"></div>

    <!-- Detail panel -->
    <div id="detail-panel">
        <div id="detail-header">
            <h2 id="detail-title">Span detail</h2>
            <button id="detail-close" title="Close">×</button>
        </div>
        <div id="detail-tabs">
            <button class="tab-btn active" data-tab="prompt">Prompt</button>
            <button class="tab-btn" data-tab="completion">Response</button>
            <button class="tab-btn" data-tab="meta">Meta</button>
            <button class="tab-btn" data-tab="trace">Trace I/O</button>
        </div>
        <div id="detail-body">
            <p style="color:var(--muted);text-align:center;margin-top:40px">Select a span to view details.</p>
        </div>
        <div id="msg-nav" class="hidden">
            <button id="msg-nav-top"  class="nav-edge" title="First message"><span class="nav-bar"></span>▲</button>
            <button id="msg-nav-up"   title="Previous message">▲</button>
            <button id="msg-nav-down" title="Next message">▼</button>
            <button id="msg-nav-bot"  class="nav-edge" title="Last message">▼<span class="nav-bar"></span></button>
        </div>
    </div>
</div><!-- /main-area -->

<div id="stats-footer">
    <div class="stat-card">
        <div class="label">Total spans</div>
        <div class="value" id="stat-spans">—</div>
    </div>
    <div class="stat-card">
        <div class="label">Total cost</div>
        <div class="value" id="stat-cost">—</div>
    </div>
    <div class="stat-card">
        <div class="label">Avg duration</div>
        <div class="value" id="stat-dur">—</div>
    </div>
    <div class="stat-card">
        <div class="label">Total tokens</div>
        <div class="value" id="stat-tokens">—</div>
    </div>
</div>

<script>
(function () {
'use strict';

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------
const API_BASE = <?= json_encode($VIEWER_API_BASE, JSON_UNESCAPED_SLASHES) ?>;

function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function fmtCost(v) {
    const n = parseFloat(v);
    if (isNaN(n)) return '—';
    return '$' + n.toFixed(6).replace(/\.?0+$/, '');
}

function fmtNum(v) {
    if (v == null || v === '') return '—';
    return Number(v).toLocaleString();
}

function fmtDur(ms) {
    if (ms == null || ms === '') return '—';
    const n = parseInt(ms);
    if (n < 1000) return n + ' ms';
    return (n / 1000).toFixed(2) + ' s';
}

function fmtStartedAtLocal(value) {
    if (!value) return '—';

    const match = String(value).trim().match(
        /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?$/
    );
    if (!match) return String(value);

    const [, year, month, day, hour, minute, second, ms = '0'] = match;
    const utcDate = new Date(Date.UTC(
        Number(year),
        Number(month) - 1,
        Number(day),
        Number(hour),
        Number(minute),
        Number(second),
        Number(ms.padEnd(3, '0'))
    ));

    return utcDate.toLocaleString([], {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
    });
}

function durClass(ms) {
    const n = parseInt(ms);
    if (isNaN(n)) return '';
    if (n < 1000) return 'dur-green';
    if (n < 3000) return 'dur-amber';
    return 'dur-red';
}

function finishBadge(r) {
    if (!r) return '';
    const cls = r === 'stop' ? 'badge-stop' : r === 'length' ? 'badge-length' : r.includes('error') ? 'badge-error' : '';
    return `<span class="badge ${cls}">${escapeHtml(r)}</span>`;
}

function trunc(s, n) {
    if (!s) return '';
    return s.length > n ? s.slice(0, n) + '…' : s;
}

function apiUrl(action, params = {}) {
    const query = new URLSearchParams({ _action: action, ...params });
    return (API_BASE ? API_BASE : '') + '?' + query.toString();
}

function renderEscapedTextWithBreaks(value) {
    return escapeHtml(value)
        .replace(/\\n/g, '<br/>')
        .replace(/\n/g, '<br/>');
}

function renderJsonBlock(raw) {
    if (!raw) return '';

    let formatted;
    try {
        formatted = JSON.stringify(JSON.parse(raw), null, 2);
    } catch (e) {
        return `<pre class="json-view">${renderEscapedTextWithBreaks(raw)}</pre>`;
    }

    const highlighted = escapeHtml(formatted).replace(
        /(&quot;(?:\\u[\da-fA-F]{4}|\\[^u]|[^\\&]|&(?!quot;))*&quot;)(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+\-]?\d+)?/g,
        (match, quoted, isKey, keyword) => {
            if (quoted) {
                return `<span class="${isKey ? 'json-key' : 'json-string'}">${quoted}</span>${isKey || ''}`;
            }
            if (keyword) {
                return `<span class="${keyword === 'null' ? 'json-null' : 'json-boolean'}">${keyword}</span>`;
            }
            return `<span class="json-number">${match}</span>`;
        }
    );

    return `<pre class="json-view">${highlighted.replace(/\\n/g, '<br/>')}</pre>`;
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const state = {
    sort: 'started_at',
    dir: 'DESC',
    page: 1,
    search: '',
    hide: new Set(),
    total: 0,
    filteredMode: false,
    filteredHasMore: false,
    filteredNextOffset: 0,
    filteredLoaded: 0,
    filteredTruncated: false,
    activeId: null,
    activeTab: 'prompt',
    detailCache: {},
    detailDisclosureState: {},
};

function syncFilterStateToUrl() {
    const url = new URL(window.location.href);
    const search = state.search.trim();
    const hide = [...state.hide].sort().join(',');

    if (search !== '') {
        url.searchParams.set('search', search);
    } else {
        url.searchParams.delete('search');
    }

    if (hide !== '') {
        url.searchParams.set('hide', hide);
    } else {
        url.searchParams.delete('hide');
    }

    history.replaceState(null, '', url);
}

function restoreFilterStateFromUrl() {
    const params = new URLSearchParams(window.location.search);
    const search = (params.get('search') || '').trim();
    const hide = (params.get('hide') || '')
        .split(',')
        .map(value => value.trim())
        .filter(value => value === 'cron' || value === 'heartbeat' || value === 'other');

    state.search = search;
    state.hide = new Set(hide);

    const searchInput = document.getElementById('search-filter');
    if (searchInput) {
        searchInput.value = search;
    }

    document.querySelectorAll('.hide-toggle').forEach(btn => {
        btn.classList.toggle('active', state.hide.has(btn.dataset.type));
    });

    updateClearFiltersButton();
}

function setRefreshBusy(isBusy) {
    const button = document.getElementById('refresh-dashboard');
    if (!button) return;
    button.disabled = isBusy;
    button.classList.toggle('is-loading', isBusy);
    button.setAttribute('aria-busy', isBusy ? 'true' : 'false');
}

function updateClearFiltersButton() {
    const button = document.getElementById('clear-filters');
    if (!button) return;
    const hasActiveFilters = state.search.trim() !== '' || state.hide.size > 0;
    button.disabled = !hasActiveFilters;
    button.setAttribute('aria-disabled', hasActiveFilters ? 'false' : 'true');
}

function clearFilters() {
    state.search = '';
    state.hide = new Set();
    state.page = 1;
    resetFilteredState();

    const searchInput = document.getElementById('search-filter');
    if (searchInput) {
        searchInput.value = '';
    }

    document.querySelectorAll('.hide-toggle').forEach(btn => {
        btn.classList.remove('active');
    });

    updateClearFiltersButton();
    syncFilterStateToUrl();
    loadSpans();
}

async function refreshDashboard() {
    setRefreshBusy(true);
    state.detailCache = {};
    try {
        await Promise.all([loadStats(), loadSpans()]);
        if (state.activeId != null) {
            await openDetail(state.activeId);
        }
    } finally {
        setRefreshBusy(false);
    }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------
async function loadStats() {
    try {
        const r = await fetch(apiUrl('stats'));
        const d = await r.json();
        document.getElementById('stat-spans').textContent  = fmtNum(d.total_spans);
        document.getElementById('stat-cost').textContent   = fmtCost(d.total_cost);
        document.getElementById('stat-dur').textContent    = fmtDur(d.avg_duration_ms);
        document.getElementById('stat-tokens').textContent = fmtNum(d.total_tokens);
    } catch (e) {
        console.error('Stats error', e);
    }
}

// ---------------------------------------------------------------------------
// Spans table
// ---------------------------------------------------------------------------
function resetFilteredState() {
    state.filteredMode = false;
    state.filteredHasMore = false;
    state.filteredNextOffset = 0;
    state.filteredLoaded = 0;
    state.filteredTruncated = false;
}

async function loadSpans(options = {}) {
    const append = !!options.append;
    const body = document.getElementById('spans-body');
    document.getElementById('table-area').classList.add('page-loading');
    if (!append) {
        body.innerHTML = '<tr class="state-row"><td colspan="11"><span class="spinner"></span>Loading…</td></tr>';
    }

    const params = new URLSearchParams({
        sort: state.sort,
        dir: state.dir,
        page: state.page,
        search: state.search,
        hide: [...state.hide].join(','),
    });
    if (state.hide.size > 0) {
        params.set('scan_offset', append ? state.filteredNextOffset : 0);
    }

    let data;
    try {
        try {
            const r = await fetch(apiUrl('spans', Object.fromEntries(params.entries())));
            data = await r.json();
        } catch (e) {
            if (!append) {
                body.innerHTML = '<tr class="state-row"><td colspan="11">Failed to load data.</td></tr>';
            }
            renderPagination();
            return;
        }

    state.filteredMode = !!data.filtered;
    state.filteredHasMore = !!data.has_more;
    state.filteredNextOffset = Number(data.next_offset || 0);
    state.filteredTruncated = !!data.scan_truncated;
    state.total = data.total || 0;
    const spans = data.spans || [];
    if (state.filteredMode) {
        state.filteredLoaded = append ? state.filteredLoaded + spans.length : spans.length;
    } else {
        state.filteredLoaded = 0;
    }

    if (spans.length === 0 && !append) {
        body.innerHTML = '<tr class="state-row"><td colspan="11">No spans found.</td></tr>';
        renderPagination();
        return;
    }
    if (spans.length === 0 && append) {
        renderPagination();
        return;
    }

    const rows = spans.map(s => {
        const active = s.id == state.activeId ? ' class="active"' : '';
        const durCls = durClass(s.duration_ms);
        return `<tr data-id="${escapeHtml(s.id)}"${active}>
            <td class="td-mono" data-label="Started">${escapeHtml(fmtStartedAtLocal(s.started_at || s.started_at_fmt || ''))}</td>
            ${s.cron_name
                ? `<td data-label="Prompt"><span class="badge badge-cron">CRON</span> ${escapeHtml(s.cron_name)}</td>`
                : s.heartbeat
                    ? `<td data-label="Prompt"><span class="badge badge-heartbeat">HEARTBEAT</span></td>`
                    : `<td class="td-preview" data-label="Prompt">${escapeHtml(trunc(s.prompt_preview || '', 100))}</td>`
            }
            <td class="td-preview" data-label="Result">${escapeHtml(trunc(s.response_preview || '', 100))}</td>
            <td data-label="Finish">${finishBadge(s.finish_reason)}</td>
            <td class="${durCls}" data-label="Duration">${fmtDur(s.duration_ms)}</td>
            <td class="td-mono" data-label="Req Model">${escapeHtml(trunc(s.request_model_short  || s.request_model  || '—', 28))}</td>
            <td class="td-mono" data-label="Resp Model">${escapeHtml(trunc(s.response_model_short || s.response_model || '—', 28))}</td>
            <td class="td-right" data-label="In Tok">${fmtNum(s.input_tokens)}</td>
            <td class="td-right" data-label="Out Tok">${fmtNum(s.output_tokens)}</td>
            <td class="td-right" data-label="Cache">${fmtNum(s.cached_tokens)}</td>
            <td class="td-right td-mono" data-label="Cost">${fmtCost(s.total_cost_usd)}</td>
        </tr>`;
    });
    if (append) {
        body.insertAdjacentHTML('beforeend', rows.join(''));
    } else {
        body.innerHTML = rows.join('');
    }

    // Row click → open detail
    body.querySelectorAll('tr[data-id]').forEach(tr => {
        tr.addEventListener('click', () => openDetail(parseInt(tr.dataset.id)));
    });

    renderPagination();
    updateSortHeaders();
    } finally {
        document.getElementById('table-area').classList.remove('page-loading');
    }
}

// ---------------------------------------------------------------------------
// Sort
// ---------------------------------------------------------------------------
document.querySelectorAll('thead th[data-col]').forEach(th => {
    th.addEventListener('click', () => {
        const col = th.dataset.col;
        if (state.sort === col) {
            state.dir = state.dir === 'DESC' ? 'ASC' : 'DESC';
        } else {
            state.sort = col;
            state.dir = 'DESC';
        }
        state.page = 1;
        resetFilteredState();
        loadSpans();
    });
});

function updateSortHeaders() {
    document.querySelectorAll('thead th[data-col]').forEach(th => {
        th.classList.remove('sort-asc', 'sort-desc');
        if (th.dataset.col === state.sort) {
            th.classList.add(state.dir === 'ASC' ? 'sort-asc' : 'sort-desc');
        }
    });
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------
function renderPagination() {
    const el = document.getElementById('pagination');
    if (state.filteredMode) {
        if (!state.filteredHasMore) {
            el.innerHTML = state.filteredLoaded > 0
                ? '<span class="page-ellipsis">End of filtered results</span>'
                : '';
            return;
        }
        el.innerHTML = `<button class="page-btn" id="load-more-filtered">Load more</button>`;
        const button = document.getElementById('load-more-filtered');
        button.addEventListener('click', async () => {
            button.disabled = true;
            button.textContent = 'Loading…';
            await loadSpans({ append: true });
        });
        return;
    }

    const per    = 50;
    const total  = state.total;
    const pages  = Math.max(1, Math.ceil(total / per));
    const cur    = state.page;

    if (pages <= 1) { el.innerHTML = ''; return; }

    const pageItems = [];
    const addPage = (page) => {
        pageItems.push({ type: 'page', page });
    };
    const addEllipsis = () => {
        if (pageItems[pageItems.length - 1]?.type !== 'ellipsis') {
            pageItems.push({ type: 'ellipsis' });
        }
    };

    addPage(1);

    const windowStart = Math.max(2, cur - 2);
    const windowEnd   = Math.min(pages - 1, cur + 2);

    if (windowStart > 2) addEllipsis();
    for (let page = windowStart; page <= windowEnd; page++) {
        addPage(page);
    }
    if (windowEnd < pages - 1) addEllipsis();

    if (pages > 1) addPage(pages);

    el.innerHTML = pageItems.map(item => {
        if (item.type === 'ellipsis') {
            return '<span class="page-ellipsis">…</span>';
        }
        const active = item.page === cur ? ' active' : '';
        return `<button class="page-btn${active}" data-page="${item.page}">${item.page}</button>`;
    }).join('');

    el.querySelectorAll('button[data-page]').forEach(button => {
        button.addEventListener('click', () => {
            const nextPage = parseInt(button.dataset.page, 10);
            if (nextPage === state.page) return;
            state.page = nextPage;
            loadSpans();
        });
    });
}

// ---------------------------------------------------------------------------
// Model filter (debounced)
// ---------------------------------------------------------------------------
let filterTimer;
document.getElementById('search-filter').addEventListener('input', function () {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(() => {
        state.search = this.value.trim();
        state.page   = 1;
        resetFilteredState();
        updateClearFiltersButton();
        syncFilterStateToUrl();
        loadSpans();
    }, 350);
});

document.querySelectorAll('.hide-toggle').forEach(btn => {
    btn.addEventListener('click', function () {
        const type = this.dataset.type;
        if (state.hide.has(type)) {
            state.hide.delete(type);
            this.classList.remove('active');
        } else {
            state.hide.add(type);
            this.classList.add('active');
            const allTypes = ['cron', 'heartbeat', 'other'];
            if (allTypes.every(t => state.hide.has(t))) {
                allTypes.filter(t => t !== type).forEach(t => {
                    state.hide.delete(t);
                    document.querySelector(`.hide-toggle[data-type="${t}"]`)
                        ?.classList.remove('active');
                });
            }
        }
        state.page = 1;
        resetFilteredState();
        updateClearFiltersButton();
        syncFilterStateToUrl();
        loadSpans();
    });
});

document.getElementById('clear-filters').addEventListener('click', () => {
    clearFilters();
});

document.getElementById('refresh-dashboard').addEventListener('click', () => {
    refreshDashboard();
});

// ---------------------------------------------------------------------------
// Detail panel
// ---------------------------------------------------------------------------
async function openDetail(id) {
    state.activeId = id;

    // Highlight active row
    document.querySelectorAll('#spans-body tr.active').forEach(r => r.classList.remove('active'));
    const row = document.querySelector(`#spans-body tr[data-id="${id}"]`);
    if (row) row.classList.add('active');

    // Open panel
    const panel = document.getElementById('detail-panel');
    const backdrop = document.getElementById('detail-backdrop');
    panel.classList.add('open');
    backdrop.classList.add('open');
    document.getElementById('table-area').classList.add('panel-open');

    // Show loading in body
    document.getElementById('detail-body').innerHTML =
        '<p style="text-align:center;padding:40px;color:var(--muted)"><span class="spinner"></span>Loading…</p>';

    // Fetch (or use cache)
    let data;
    if (state.detailCache[id]) {
        data = state.detailCache[id];
    } else {
        try {
            const r = await fetch(apiUrl('detail', { id }));
            data = await r.json();
            state.detailCache[id] = data;
        } catch (e) {
            document.getElementById('detail-body').innerHTML =
                '<p style="color:var(--red);padding:16px">Failed to load detail.</p>';
            return;
        }
    }

    document.getElementById('detail-title').textContent =
        trunc(data.span?.trace_name || 'Span #' + id, 40);

    renderDetailPanel(data, state.activeTab);
}

// ---------------------------------------------------------------------------
// Tab switching
// ---------------------------------------------------------------------------
document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', function () {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        this.classList.add('active');
        state.activeTab = this.dataset.tab;
        if (state.activeId && state.detailCache[state.activeId]) {
            renderDetailPanel(state.detailCache[state.activeId], state.activeTab);
        }
    });
});

// ---------------------------------------------------------------------------
// Close panel
// ---------------------------------------------------------------------------
function closeDetailPanel() {
    document.getElementById('detail-panel').classList.remove('open');
    document.getElementById('detail-backdrop').classList.remove('open');
    document.getElementById('table-area').classList.remove('panel-open');
    document.querySelectorAll('#spans-body tr.active').forEach(r => r.classList.remove('active'));
    state.activeId = null;
}

document.getElementById('detail-close').addEventListener('click', closeDetailPanel);

// ---------------------------------------------------------------------------
// Render detail panel
// ---------------------------------------------------------------------------
function renderDetailPanel(data, tab) {
    const body = document.getElementById('detail-body');
    if (tab === 'meta')       { body.innerHTML = renderMeta(data.span); }
    else if (tab === 'prompt')     { body.innerHTML = renderPromptTab(data); }
    else if (tab === 'completion') { body.innerHTML = renderCompletionTab(data); }
    else if (tab === 'trace')      { body.innerHTML = renderTraceTab(data); }
    bindPersistentDisclosures(body);
    updateMsgNav(tab);
}

function bindPersistentDisclosures(container) {
    container.querySelectorAll('details[data-persist-key]').forEach(el => {
        const key = el.dataset.persistKey;
        if (Object.prototype.hasOwnProperty.call(state.detailDisclosureState, key)) {
            el.open = !!state.detailDisclosureState[key];
        }
        el.addEventListener('toggle', () => {
            state.detailDisclosureState[key] = el.open;
        });
    });
}

// ---------------------------------------------------------------------------
// Message navigation
// ---------------------------------------------------------------------------
let _msgNodes = [];
let _msgIdx   = 0;

function updateMsgNav(tab) {
    const nav = document.getElementById('msg-nav');
    if (tab !== 'prompt') { nav.classList.add('hidden'); return; }
    _msgNodes = [...document.querySelectorAll('#detail-body .chat-wrap > div')];
    if (_msgNodes.length <= 1) { nav.classList.add('hidden'); return; }
    _msgIdx = 0;
    nav.classList.remove('hidden');
    refreshMsgNavBtns();
}

function refreshMsgNavBtns() {
    document.getElementById('msg-nav-top').disabled  = _msgIdx <= 0;
    document.getElementById('msg-nav-up').disabled   = _msgIdx <= 0;
    document.getElementById('msg-nav-down').disabled = _msgIdx >= _msgNodes.length - 1;
    document.getElementById('msg-nav-bot').disabled  = _msgIdx >= _msgNodes.length - 1;
}

function scrollToMsg(idx) {
    _msgIdx = Math.max(0, Math.min(idx, _msgNodes.length - 1));
    const body   = document.getElementById('detail-body');
    const target = _msgNodes[_msgIdx];
    if (target) {
        const bodyTop   = body.getBoundingClientRect().top;
        const targetTop = target.getBoundingClientRect().top;
        body.scrollTop += targetTop - bodyTop;
        flashMsgLabel(target);
    }
    refreshMsgNavBtns();
}

function flashMsgLabel(target) {
    const label = target?.querySelector('.msg-role-label');
    if (!label) return;
    label.classList.remove('is-flashing');
    void label.offsetWidth;
    label.classList.add('is-flashing');
}

document.getElementById('msg-nav-top').addEventListener('click',  () => scrollToMsg(0));
document.getElementById('msg-nav-up').addEventListener('click',   () => scrollToMsg(_msgIdx - 1));
document.getElementById('msg-nav-down').addEventListener('click', () => scrollToMsg(_msgIdx + 1));
document.getElementById('msg-nav-bot').addEventListener('click',  () => scrollToMsg(_msgNodes.length - 1));

function renderMeta(span) {
    if (!span) return '<p style="color:var(--muted)">No data.</p>';
    const skip = new Set(['span_input','span_output','trace_input','trace_output','gen_ai_prompt','gen_ai_completion']);
    let html = '<div class="meta-grid">';
    for (const [k, v] of Object.entries(span)) {
        if (skip.has(k) || v == null || v === '') continue;
        html += `<div class="meta-key">${escapeHtml(k)}</div>`;
        html += `<div class="meta-val">${escapeHtml(String(v))}</div>`;
    }
    html += '</div>';
    return html;
}

function renderPromptTab(data) {
    const msgs = (data.gen_ai_messages && data.gen_ai_messages.length)
        ? data.gen_ai_messages
        : data.span_messages;

    if (!msgs || msgs.length === 0) {
        return '<p style="color:var(--muted);text-align:center;padding:24px">No prompt messages found.</p>';
    }
    return '<div class="chat-wrap">' + msgs.map(renderMessage).join('') + '</div>';
}

function renderCompletionTab(data) {
    const parsed = (data.gen_ai_completion_parsed?.completion != null)
        ? data.gen_ai_completion_parsed
        : data.span_output_parsed;

    if (!parsed || (parsed.completion == null && !parsed.reasoning && (!parsed.tools || parsed.tools.length === 0))) {
        return '<p style="color:var(--muted);text-align:center;padding:24px">No completion data found.</p>';
    }

    let html = '';
    if (parsed.completion != null) {
        html += renderMessage({ role: 'assistant', content: parsed.completion });
    }
    if (parsed.reasoning) {
        html += `<details class="collapsible" data-persist-key="completion-reasoning"><summary>Reasoning</summary><div class="detail-content">${renderEscapedTextWithBreaks(parsed.reasoning)}</div></details>`;
    }
    if (parsed.tools && parsed.tools.length > 0) {
        html += `<details class="collapsible" data-persist-key="completion-tools"><summary>Tool calls (${parsed.tools.length})</summary><div class="detail-content">${renderJsonBlock(JSON.stringify(parsed.tools, null, 2))}</div></details>`;
    }
    return html;
}

function renderTraceTab(data) {
    const ti = data.trace_input_raw;
    const to = data.trace_output_raw;
    if (!ti && !to) {
        return '<p style="color:var(--muted);text-align:center;padding:24px">No trace I/O data.</p>';
    }
    let html = '';
    if (ti) {
        html += `<details class="collapsible" open data-persist-key="trace-input"><summary>Trace Input</summary><div class="detail-content">${renderJsonBlock(ti)}</div></details>`;
    }
    if (to) {
        html += `<details class="collapsible" open data-persist-key="trace-output"><summary>Trace Output</summary><div class="detail-content">${renderJsonBlock(to)}</div></details>`;
    }
    return html;
}

function renderMessage(msg) {
    const role    = msg.role || 'unknown';
    const content = msg.content;

    const roleClass = {
        system:    'msg-system',
        user:      'msg-user',
        assistant: 'msg-assistant',
        tool:      'msg-tool',
    }[role] || 'msg-assistant';

    let inner = '';
    if (content == null) {
        inner = '<em style="color:var(--muted)">(empty)</em>';
    } else if (typeof content === 'string') {
        inner = renderEscapedTextWithBreaks(content);
    } else if (Array.isArray(content)) {
        inner = content.map(part => {
            if (typeof part === 'string') return renderEscapedTextWithBreaks(part);
            if (!part || typeof part !== 'object') return '';
            if (part.type === 'text') return renderEscapedTextWithBreaks(part.text || '');
            // tool_use / tool_result → collapsible
            const label = part.type === 'tool_use'
                ? `Tool use: ${escapeHtml(part.name || '')}`
                : part.type === 'tool_result'
                    ? `Tool result: ${escapeHtml(part.tool_use_id || '')}`
                    : escapeHtml(part.type || 'part');
            const body = JSON.stringify(part, null, 2);
            return `<details class="collapsible"><summary>${label}</summary><div class="detail-content">${renderJsonBlock(body)}</div></details>`;
        }).join('');
    } else if (typeof content === 'object') {
        inner = renderJsonBlock(JSON.stringify(content, null, 2));
    } else {
        inner = renderEscapedTextWithBreaks(String(content));
    }

    return `<div>
        <div class="msg-role-label">${escapeHtml(role)}</div>
        <div class="msg-bubble ${roleClass}">${inner}</div>
    </div>`;
}

// ---------------------------------------------------------------------------
// Keyboard navigation
// ---------------------------------------------------------------------------
document.addEventListener('keydown', function (e) {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
    if (e.key === 'Escape' && state.activeId != null) {
        closeDetailPanel();
        return;
    }
    if (e.key !== 'ArrowUp' && e.key !== 'ArrowDown') return;
    e.preventDefault();

    const rows = [...document.querySelectorAll('#spans-body tr[data-id]')];
    if (rows.length === 0) return;

    let idx = rows.findIndex(r => r.dataset.id == state.activeId);
    if (e.key === 'ArrowDown') idx = idx < 0 ? 0 : Math.min(idx + 1, rows.length - 1);
    if (e.key === 'ArrowUp')   idx = idx < 0 ? rows.length - 1 : Math.max(idx - 1, 0);

    const target = rows[idx];
    openDetail(parseInt(target.dataset.id));
    target.scrollIntoView({ block: 'nearest' });
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
restoreFilterStateFromUrl();
refreshDashboard();

// ---------------------------------------------------------------------------
// Burger menu
// ---------------------------------------------------------------------------
const burgerToggle   = document.getElementById('burger-toggle');
const burgerDropdown = document.getElementById('burger-dropdown');
if (burgerToggle) {
    burgerToggle.addEventListener('click', (e) => {
        e.stopPropagation();
        burgerDropdown.hidden = !burgerDropdown.hidden;
    });
    document.addEventListener('click', () => {
        burgerDropdown.hidden = true;
    });
    burgerDropdown.addEventListener('click', (e) => e.stopPropagation());
}

})();
</script>

<?php endif; ?>
</body>
</html>
