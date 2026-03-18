Ich möchte ein Dashboard, welches auf Basis der Datenbank die Trace-Ereignisse darstellt. 

Dabei soll eine tabellarische Darstellung stattfinden, sortierbar und standardmäßig sortiert nach   
started_at in dem die wichtigsten Infos (z.B. Token in/out, Cache, Kosten, finish_reason request-/response_modell, duration) übersichtlich kompakt dargestellt werden. 

Dann soll es möglich sein sich Input/Output etc im drilldown anzuschauen, dabei soll das json nicht "raw" dargestellt werden sondern aufbereitet (durch Analyse von rawpayload*.json). 

Das Dashboard soll primär lightmode implementieren 
Es soll im Verzeichnis "public/webhookviewer.php" abgelegt werden 

Beim Implementieren soll clean code berücksichtigt werden.
Es soll - sofern erforderlich - neueste versionen von Abhängigkeiten verwendet werden.

Verwende den Claude-Skill "data-visualization" skill und installiere ihn soweit noch nicht verfügbar: npx skillfish add robertpelloni/borg panel-dashboards         

----

The plan is ready. A few notes on scope before implementation:
                                                                                                                                                                                                
  1. data-visualization skill / skillfish: npx skillfish add robertpelloni/borg panel-dashboards is not a recognized Claude Code skill command. The plan uses Chart.js 4.x via CDN for          
  visualizations instead — no installation needed.                                                                                                                                              
  2. viewer_password: You'll need to manually add a value for this key in your live config/config.php after I create the example entry.                                                         
  3. Single-file approach: ~600–700 lines in public/webhookviewer.php with embedded CSS/JS — no new dependencies, works cleanly on shared hosting.                                              
                                                                                                                                                                                                
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
 Ready to code?                                                                                                                                                                                 
                                                                                                                                                                                                
 Here is Claude's plan:
╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
 Plan: OpenRouter Trace Dashboard (webhookviewer.php)         

 Context

 The project is a PHP webhook receiver for OpenRouter OTLP traceability data. No web UI exists yet. The user wants a read-only dashboard that queries the traces DB table and displays span
 data in a sortable table with a drilldown pane for formatted input/output views.

 Note on data-visualization skill: npx skillfish add robertpelloni/borg panel-dashboards is not a recognized Claude Code skill command. Proceeding with Chart.js 4.x via CDN for any
 visualizations.

 ---
 Files to Create / Modify

 ┌───────────────────────────┬─────────────────────────────────────────────────┐
 │           File            │                     Action                      │
 ├───────────────────────────┼─────────────────────────────────────────────────┤
 │ public/webhookviewer.php  │ Create — single-file dashboard (~600–700 lines) │
 ├───────────────────────────┼─────────────────────────────────────────────────┤
 │ public/.htaccess          │ Edit — add /mywebhookviewer/ rewrite rule       │
 ├───────────────────────────┼─────────────────────────────────────────────────┤
 │ config/config.example.php │ Edit — add viewer_password key                  │
 └───────────────────────────┴─────────────────────────────────────────────────┘

 Existing files used (read-only at runtime):
 - src/Database.php — instantiated via new Database($config['db']), call getConnection() for PDO
 - config/config.php — loaded with require __DIR__ . '/../config/config.php'

---
 URL Routing

 Update public/.htaccess — add before the catch-all rule:

 # Dashboard: /mywebhookviewer/ and /mywebhookviewer → webhookviewer.php
 RewriteRule ^mywebhookviewer/?$ webhookviewer.php [L,QSA]

 QSA preserves ?_action=spans&page=1 etc. for JS API calls.
 All JS fetch() calls use ?_action=... relative to the current URL so they work regardless of path.

 ---
 Architecture: Single-File, Action Router

 webhookviewer.php
 │
 ├── PHP header
 │   ├── error suppression (ini_set)
 │   ├── require Database.php + config.php
 │   ├── session_set_cookie_params ([httponly, samesite=Lax])
 │   └── session_start()
 │
 ├── Pure PHP functions
 │   ├── Auth: viewer_check_auth(), viewer_do_login(), viewer_do_logout()
 │   ├── DB queries: db_get_spans(), db_count_spans(), db_get_stats(), db_get_detail()
 │   ├── Content parsing: parse_messages_field(), parse_completion_field()
 │   └── Action handlers: action_spans(), action_detail(), action_stats()
 │
 ├── Action router (?_action=spans|detail|stats)
 │   └── All actions: auth-check → DB connect → JSON response → exit
 │
 ├── Login/logout POST handler
 │
 └── HTML output
     ├── If not authed: login form
     └── If authed: full dashboard shell

 API Actions

 ┌─────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │  ?_action=  │                                                         Response                                                          │
 ├─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ spans       │ {spans:[...], total:N, page:N} — paginated list (50/page), sortable                                                       │
 ├─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ detail&id=X │ {span:{...scalars}, gen_ai_messages:[...], gen_ai_completion_parsed:{...}, span_messages:[...], span_output_parsed:{...}} │
 ├─────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ stats       │ {total_spans, total_cost, avg_duration_ms, total_tokens}                                                                  │
 └─────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

---
 Table Columns (default sort: started_at DESC)

 ┌────────────────┬─────────────────────────────────────────────┐
 │     Column     │                    Notes                    │
 ├────────────────┼─────────────────────────────────────────────┤
 │ started_at     │ formatted as Y-m-d H:i:s                    │
 ├────────────────┼─────────────────────────────────────────────┤
 │ trace_name     │ truncated to 30 chars                       │
 ├────────────────┼─────────────────────────────────────────────┤
 │ request_model  │ shortened (strip provider prefix)           │
 ├────────────────┼─────────────────────────────────────────────┤
 │ response_model │ shortened                                   │
 ├────────────────┼─────────────────────────────────────────────┤
 │ duration_ms    │ color-coded: green <1s, amber 1–3s, red >3s │
 ├────────────────┼─────────────────────────────────────────────┤
 │ input_tokens   │ right-aligned                               │
 ├────────────────┼─────────────────────────────────────────────┤
 │ output_tokens  │ right-aligned                               │
 ├────────────────┼─────────────────────────────────────────────┤
 │ cached_tokens  │ right-aligned                               │
 ├────────────────┼─────────────────────────────────────────────┤
 │ total_cost_usd │ formatted $0.000000                         │
 ├────────────────┼─────────────────────────────────────────────┤
 │ finish_reason  │ badge-styled                                │
 └────────────────┴─────────────────────────────────────────────┘

 Sort: allowlist validated in PHP (in_array($col, $ALLOWED, true)), interpolated into SQL (not bound param — PDO limitation). Direction validated against ['ASC','DESC'].

 ---
 Drilldown Panel

 Slides in from right (fixed, 480px, transform: translateX(0)).

 PHP pre-parses JSON strings server-side so JS receives clean arrays:

 function parse_messages_field(?string $json): array {
     if (!$json) return [];
     $decoded = json_decode($json, true);
     return $decoded['messages'] ?? [];
 }

 function parse_completion_field(?string $json): array {
     if (!$json) return [];
     $decoded = json_decode($json, true) ?? [];
     return [
         'completion' => $decoded['completion'] ?? null,
         'reasoning'  => $decoded['reasoning'] ?? null,
         'tools'      => $decoded['tools'] ?? [],
     ];
 }

Drilldown sections:
 1. Meta grid — all scalar fields in a 2-col key/value grid
 2. Prompt — gen_ai_prompt (or span_input) as chat bubbles
 3. Completion — gen_ai_completion (or span_output) as assistant bubble + collapsible reasoning/tools
 4. Trace I/O — trace_input/trace_output if present, in <details>

 Chat bubble rendering (JS):
 - role=system → light blue left-border card
 - role=user → light blue bubble (right-aligned)
 - role=assistant → light gray bubble
 - role=tool → monospace yellow-bordered card
 - Content: string → textContent (XSS-safe). Array (multipart) → iterate parts, tool_use/tool_result as <details>

 ---
 CSS: Light Mode

 All in <style> block. CSS custom properties for design tokens:

 :root {
     --bg: #fff; --surface: #f8f9fa; --border: #e0e3e8;
     --text: #1a1d23; --muted: #6b7280; --accent: #2563eb;
     --green: #16a34a; --amber: #d97706; --red: #dc2626;
 }

 Layout: body flex column → header → stats-bar (4 cards) → main (table + hidden detail panel).

 ---
 Security

 ┌───────────────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
 │    Concern    │                                                                     Mitigation                                                                      │
 ├───────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ SQL injection │ PDO bound params for all values; sort col/dir from allowlist only                                                                                   │
 ├───────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ XSS           │ All DB data through htmlspecialchars() in PHP; textContent in JS; escapeHtml() helper                                                               │
 ├───────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ CSRF          │ $_SESSION['csrf_token'] checked on login/logout POST                                                                                                │
 ├───────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Session       │ session_regenerate_id(true) on login; session_destroy() on logout; httponly+samesite=Lax cookie                                                     │
 ├───────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Auth          │ hash_equals() for password compare; sleep(1) on failure                                                                                             │
 ├───────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ Info leak     │ PHP errors suppressed; DB errors return generic JSON; raw_payload excluded from queries                                                             │
 ├───────────────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┤
 │ CSP           │ header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'") │
 └───────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘

 ---
 Config Change

 Add to config/config.example.php:
 // Dashboard viewer password (for /mywebhookviewer/)
 'viewer_password' => 'DEIN_VIEWER_PASSWORT',

 User must set a real value in their config/config.php before use.

 ---
 Implementation Steps

 1. Edit config/config.example.php — add viewer_password
 2. Edit public/.htaccess — add /mywebhookviewer/ rewrite before catch-all
 3. Create public/webhookviewer.php:
 a. PHP bootstrap + auth functions + login form HTML
 b. DB query functions + action router + API endpoints
 c. HTML shell (authenticated) with stats bar, table, detail panel
 d. CSS (all inline in <style>)
 e. JS: state, loadSpans(), sort/pagination, loadStats()
 f. JS: drilldown openDetail(), renderDetailPanel(), chat bubble rendering

 ---
 Verification

 1. Visit /mywebhookviewer/ → login form shown
 2. Enter viewer_password → dashboard with table loads
 3. Verify sort clicking changes sort order
 4. Verify pagination works with real data
 5. Click a row → detail panel slides in with formatted chat view
 6. Visit /webhookviewer.php directly → also works
 7. curl -s 'https://your-url/mywebhookviewer/?_action=spans' → {"error":"Unauthorized"} (401)
 8. Verify webhook.php POST still works unchanged
