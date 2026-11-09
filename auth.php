<?php
/* دفتر فاکتور — ورود بدون رمز: اثر انگشت / چهره (WebAuthn) و کد پیامکی
   هر دو فقط روی «دستگاه مورد اعتماد» کار می‌کنند (inc/passkey.php)، چون کلید داده باید با راز همان دستگاه باز شود.
   پاسخ‌ها JSON؛ توکن CSRF همان توکن فرم ورود است (هدر X-CSRF-Token). */
declare(strict_types=1);
define('DF', 1);
require __DIR__ . '/inc/lib.php';

df_headers('api');
df_session_start();
header('Content-Type: application/json; charset=utf-8');
$out = function (array $d, int $code = 200): void { http_response_code($code); echo json_encode($d, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES); exit; };
if ($_SERVER['REQUEST_METHOD'] !== 'POST') $out(['ok' => false, 'error' => 'method'], 405);
if (!df_csrf_ok((string)($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ''))) $out(['ok' => false, 'error' => 'مهلت صفحه تمام شده؛ صفحه را تازه کنید.'], 403);
if (df_logged_in()) $out(['ok' => true, 'go' => df_base_path()]);
$in = json_decode((string)file_get_contents('php://input'), true);
if (!is_array($in)) $in = [];
$a = (string)($in['a'] ?? '');

$finish = function (string $user, string $need, string $how) use ($out): void {
    $wait = df_login_locked($user);
    if ($wait > 0) $out(['ok' => false, 'error' => 'به دلیل تلاش‌های ناموفق زیاد، ورود تا ' . df_fa_num((string)ceil($wait / 60)) . ' دقیقه‌ی دیگر بسته است.'], 429);
    $dek = df_dev_dek($user, $need);
    if ($dek === null) $out(['ok' => false, 'error' => 'این دستگاه برای «' . $user . '» فعال نشده است. یک بار با رمز وارد شوید و در «تنظیمات عمومی ← حساب کاربری» '
        . ($need === 'pk' ? 'اثر انگشت را برای همین دستگاه ثبت کنید.' : 'ورود با پیامک را برای همین دستگاه روشن کنید.')], 403);
    df_login_attempt($user, true);
    df_login_finish($user, $dek, null, $how);
    $out(['ok' => true, 'go' => df_base_path()]);
};

try {
    switch ($a) {
        case 'pk_options':
            if (pk_rp_id() === '') $out(['ok' => false, 'error' => 'نشانی سایت شناخته نشد.'], 500);
            $out(['ok' => true, 'options' => pk_login_options()]);
        case 'pk_login': {
            [$user, $err] = pk_login_verify((array)($in['cred'] ?? []));
            if ($user === null) $out(['ok' => false, 'error' => $err], 401);
            $finish($user, 'pk', 'اثر انگشت');
        }
        case 'otp_send': {
            $user = trim((string)($in['u'] ?? ''));
            if (!df_valid_username($user)) $out(['ok' => false, 'error' => 'نام کاربری را درست بنویسید.'], 400);
            if (($w = df_login_locked($user)) > 0) $out(['ok' => false, 'error' => 'ورود تا ' . df_fa_num((string)ceil($w / 60)) . ' دقیقه‌ی دیگر بسته است.'], 429);
            $r = sms_otp_send($user);
            $out(['ok' => $r['ok'], 'msg' => $r['msg'], 'error' => $r['ok'] ? '' : $r['msg'], 'show' => $r['show'] ?? ''], $r['ok'] ? 200 : 400);
        }
        case 'otp_login': {
            [$user, $err] = sms_otp_check((string)($in['code'] ?? ''));
            if ($user === null) $out(['ok' => false, 'error' => $err], 401);
            $finish($user, 'sms', 'پیامک');
        }
    }
} catch (Throwable $e) {
    error_log('daftar-factor auth: ' . $e->getMessage());
    $out(['ok' => false, 'error' => 'server error'], 500);
}
$out(['ok' => false, 'error' => 'unknown action'], 400);
