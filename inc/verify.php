<?php
/* دفتر فاکتور — QR تأیید اصالت سند

   روی هر سندِ ثبت‌شده یک QR چاپ می‌شود که به v.php?t=<توکن> می‌رود. توکن (۲۲ نویسه) را خود برنامه می‌سازد و فقط
   در دادهٔ رمزشدهٔ برنامه و روی کاغذ است؛ روی سرور فقط هش آن نگه داشته می‌شود.
   - نسخهٔ نمایشیِ سند، نام و شمارهٔ موبایلِ «رابط» با کلیدی ساخته‌شده از خودِ توکن رمز می‌شوند؛ پس بدون QR
     هیچ‌چیز از روی پرونده‌های سرور خوانده نمی‌شود.
   - هر کس QR را اسکن کند، یک رمزِ یک‌بارمصرف به موبایلِ رابط پیامک می‌شود؛ صفحه می‌گوید برای چه کسی و
     بخشی از شماره را نشان می‌دهد. بدون رمز، سند نمایش داده نمی‌شود.
   - هر اسکن، فرستادن رمز، رمز درست یا اشتباه و دیدن سند در گزارش (رمزشده) ثبت می‌شود. */
declare(strict_types=1);
if (!defined('DF')) { http_response_code(403); exit; }

const DF_VF_PASS_MINUTES = 30;   /* بعد از رمز درست، تا این چند دقیقه سند دیده می‌شود */
const DF_VF_CODE_MINUTES = 10;   /* اعتبار رمز پیامک‌شده */
const DF_VF_SMS_GAP = 60;        /* فاصلهٔ دو پیامک در یک مرورگر (ثانیه) */
const DF_VF_SMS_PER_HOUR = 5;    /* پیامک برای هر سند در یک ساعت */
const DF_VF_SMS_PER_DAY = 15;    /* پیامک برای هر سند در یک روز */
const DF_VF_IP_SMS_PER_HOUR = 10;/* پیامک‌هایی که یک آی‌پی در یک ساعت (روی همهٔ سندها) می‌تواند بخواهد */

function vf_valid_token(string $t): bool { return (bool)preg_match('/^[A-Za-z0-9_-]{22}$/', $t); }
function vf_hash(string $t): string { return hash('sha256', 'df-verify:' . $t); }
function vf_key(string $t): string { return hash_hmac('sha256', 'df-verify-key', $t, true); }
function vf_file(string $h): string { return df_path('verify/' . $h . '.bin'); }
function vf_all(): array { $a = df_read('verify.json', []); return is_array($a) ? $a : []; }

/** نسخهٔ نمایشی و/یا رابطِ یک سند را می‌سازد یا به‌روز می‌کند */
function vf_put(string $t, string $doc, ?string $html, string $name, string $mobile, bool $dead, string $user): array {
    $h = vf_hash($t); $k = vf_key($t);
    $old = vf_all()[$h] ?? null;
    if ($old && ($old['doc'] ?? '') !== $doc) return ['ok' => false, 'error' => 'این کد برای سند دیگری است.'];
    if (!$old && $html === null) return ['ok' => false, 'error' => 'نسخهٔ سند فرستاده نشده است.'];
    $m = sms_mobile($mobile);
    if ($html !== null) df_write_atomic(vf_file($h), df_enc($html, $k, 'verify'));
    df_update('verify.json', function (array &$all) use ($h, $k, $doc, $name, $m, $dead, $user) {
        $r = $all[$h] ?? ['doc' => $doc, 'created' => time(), 'by' => $user, 'sms' => []];
        $r['ce'] = base64_encode(df_enc(json_encode(['n' => mb_substr($name, 0, 80), 'm' => $m], JSON_UNESCAPED_UNICODE), $k, 'contact'));
        $r['dead'] = $dead ? 1 : 0; $r['upd'] = time(); $r['ub'] = $user;
        $all[$h] = $r;
    });
    return ['ok' => true, 'id' => $h];
}
function vf_contact(array $r, string $t): array {
    $j = df_dec((string)base64_decode((string)($r['ce'] ?? '')), vf_key($t), 'contact');
    $c = $j ? json_decode($j, true) : null;
    return ['n' => (string)($c['n'] ?? ''), 'm' => (string)($c['m'] ?? '')];
}
function vf_public(string $h, array $r): array {
    return ['id' => $h, 'created' => ($r['created'] ?? 0) * 1000, 'upd' => ($r['upd'] ?? 0) * 1000, 'dead' => !empty($r['dead']),
        'scans' => is_file(df_share_log_file($h)) ? count(file(df_share_log_file($h), FILE_SKIP_EMPTY_LINES | FILE_IGNORE_NEW_LINES) ?: []) : 0];
}

/** رمز یک‌بارمصرف را به رابط پیامک می‌کند (با سقف‌ها) — [ok, پیام, رمزِ حالت آزمایشی] */
function vf_send_code(string $h, string $t, array $dev): array {
    $r = vf_all()[$h] ?? null;
    if (!$r) return [false, 'این کد وجود ندارد.', ''];
    $c = vf_contact($r, $t);
    if ($c['m'] === '') return [false, 'برای این سند رابطی با شمارهٔ موبایل ثبت نشده است؛ با صادرکنندهٔ سند تماس بگیرید.', ''];
    $last = (int)($_SESSION['vf'][$h]['at'] ?? 0);
    if ($last > time() - DF_VF_SMS_GAP) return [false, 'رمز همین الان فرستاده شد؛ ' . df_fa_num((string)(DF_VF_SMS_GAP - (time() - $last))) . ' ثانیهٔ دیگر می‌توانید دوباره بخواهید.', ''];
    $ip = df_ip();
    $ipOk = df_update('verify-ip.json', function (array &$a) use ($ip) {
        foreach ($a as $k => $v) { $a[$k] = array_values(array_filter((array)$v, fn($x) => $x > time() - 3600)); if (!$a[$k]) unset($a[$k]); }
        if (count($a[$ip] ?? []) >= DF_VF_IP_SMS_PER_HOUR) return false;
        $a[$ip][] = time(); return true;
    });
    if (!$ipOk) return [false, 'از این اینترنت در یک ساعت گذشته رمزِ زیادی خواسته شده؛ کمی بعد امتحان کنید.', ''];
    $ok = df_update('verify.json', function (array &$all) use ($h) {
        if (!isset($all[$h])) return 'gone';
        $s = array_values(array_filter((array)($all[$h]['sms'] ?? []), fn($x) => $x > time() - 86400));
        if (count(array_filter($s, fn($x) => $x > time() - 3600)) >= DF_VF_SMS_PER_HOUR) return 'hour';
        if (count($s) >= DF_VF_SMS_PER_DAY) return 'day';
        $s[] = time(); $all[$h]['sms'] = $s; return 'ok';
    });
    if ($ok !== 'ok') return [false, $ok === 'gone' ? 'این کد وجود ندارد.' : 'برای این سند در ' . ($ok === 'hour' ? 'یک ساعت' : 'یک روز') . ' گذشته رمزِ زیادی فرستاده شده؛ بعداً امتحان کنید یا مستقیم با رابط تماس بگیرید.', ''];
    $code = str_pad((string)random_int(0, 99999), 5, '0', STR_PAD_LEFT);
    $tpl = sms_tpl_id('vcode') > 0 || !sms_tpl_id('otp') ? 'vcode' : 'otp';
    $res = sms_send($c['m'], $tpl, ['CODE' => $code], 'رمز QR اصالت');
    if (!$res['ok']) { df_share_log($h, 'vf_sms_fail', ['msg' => $res['msg']] + $dev); return [false, 'پیامک فرستاده نشد. با رابط یا صادرکنندهٔ سند تماس بگیرید.', '']; }
    $_SESSION['vf'][$h] = ['h' => password_hash($code, PASSWORD_DEFAULT), 'exp' => time() + DF_VF_CODE_MINUTES * 60, 'tries' => 0, 'at' => time()];
    df_share_log($h, 'vf_sms', ['to' => sms_mask($c['m'])] + $dev);
    return [true, '✓ رمز فرستاده شد.', !empty($res['test']) ? $code : ''];
}
