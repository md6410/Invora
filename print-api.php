<?php
/* دفتر فاکتور — API ایستگاه چاپ (برنامه‌ی print-agent فقط با همین فایل حرف می‌زند)

   احراز هویت با توکن ایستگاه در هدر X-Print-Token.
     POST ?do=hello    معرفی ایستگاه و فهرست چاپگرها و کاغذ هرکدام
     POST ?do=claim    کار بعدی (محتوا رمزشده با کلیدِ ساخته‌شده از توکن)
     POST ?do=status   نتیجه: printing / done / error
   و برای کاربرِ واردشده:
     GET  ?do=download[&sid=…]   بسته‌ی ZIP برنامه‌ی ایستگاه (با نشانی سایت و توکن آماده) */
declare(strict_types=1);
define('DF', 1);
require __DIR__ . '/inc/lib.php';

$do = (string)($_GET['do'] ?? '');

if ($do === 'download') {
    df_headers('api');
    df_session_start();
    if (!df_logged_in()) { http_response_code(401); header('Content-Type: text/plain; charset=utf-8'); exit('ابتدا وارد برنامه شوید.'); }
    $cfg = ['api_url' => df_base_url() . 'print-api.php', 'token' => '', 'poll_seconds' => 4, 'web_port' => 8766, 'printers' => new stdClass()];
    $sid = (string)($_GET['sid'] ?? '');
    $dek = df_dek();
    $isAdmin = !empty($_SESSION['admin']);
    session_write_close();
    if ($sid !== '' && $dek && $isAdmin) $cfg['token'] = (string)(prn_station_token($sid, $dek) ?? '');
    $cfgJson = json_encode($cfg, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $exe = isset($_GET['py']) ? null : prn_exe();
    if ($exe) {
        $files = ['InvoraPrint.exe' => (string)file_get_contents($exe['path']), 'config.json' => $cfgJson, 'README.txt' => implode("\r\n", [
            'Invora Print Station ' . $exe['ver'], '',
            '1. Unzip this folder first (do not run it from inside the ZIP).',
            '2. Double-click InvoraPrint.exe and answer Yes.',
            '   If Windows SmartScreen says "Windows protected your PC": click "More info", then "Run anyway".',
            '3. The settings page opens (http://localhost:8766): set the paper of each printer and press "Test print".', '',
            'It starts by itself when someone logs in to Windows (Task Scheduler) and starts again if it ever stops.',
            'Print jobs that arrive before anyone logs in wait in the queue and print after login.',
            'No Python or internet download is needed.',
            'To update: download again from the site and run the new InvoraPrint.exe (settings are kept).',
            'To remove: open a Command Prompt here and run:  InvoraPrint.exe uninstall',
            'Files and log: C:\\ProgramData\\InvoraPrint', ''])];
    } else {
        $files = prn_agent_files();
        if (!isset($files['agent.py'])) { http_response_code(404); header('Content-Type: text/plain; charset=utf-8'); exit('فایل‌های برنامه‌ی ایستگاه روی سایت نیست.'); }
        $files['config.json'] = $cfgJson;
    }
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="invora-print.zip"');
    echo prn_zip($files);
    exit;
}

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
$out = function (array $d, int $code = 200): void {
    http_response_code($code);
    echo json_encode($d, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
};
if ($_SERVER['REQUEST_METHOD'] !== 'POST') $out(['ok' => false, 'error' => 'method'], 405);
$body = json_decode((string)file_get_contents('php://input'), true);
if (!is_array($body)) $body = [];
if ($do === '') $do = (string)($body['do'] ?? '');
$sid = prn_station_by_token(trim((string)($_SERVER['HTTP_X_PRINT_TOKEN'] ?? ($body['token'] ?? ''))));
if ($sid === null) $out(['ok' => false, 'error' => 'توکن ایستگاه معتبر نیست.'], 401);

try {
    switch ($do) {
        case 'hello':
            prn_hello($sid, (array)($body['printers'] ?? []), (string)($body['version'] ?? ''), (string)($body['host'] ?? ''));
            $out(['ok' => true, 'station' => prn_stations()[$sid]['name'] ?? '', 'poll' => 4]);
        case 'claim':
            $out(['ok' => true, 'job' => prn_claim($sid)]);
        case 'status':
            if (!prn_status($sid, (string)($body['id'] ?? ''), (string)($body['status'] ?? ''), (string)($body['error'] ?? ''))) $out(['ok' => false, 'error' => 'کار پیدا نشد.'], 404);
            $out(['ok' => true]);
    }
} catch (Throwable $e) {
    error_log('daftar-factor print-api: ' . $e->getMessage());
    $out(['ok' => false, 'error' => 'server error'], 500);
}
$out(['ok' => false, 'error' => 'دستور نامعتبر است.'], 400);
