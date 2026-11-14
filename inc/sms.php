<?php
/* دفتر فاکتور — پیامک با پنل sms.ir (API نسخه‌ی ۱، فقط ارسال با «الگو»)

   مثل وبی: هر پیامک با الگو (send/verify) می‌رود. الگویی که شناسه‌اش ثبت نشده باشد، پیامکش نمی‌رود و دلیلش
   در گزارش پیامک می‌نشیند. sms.ir مقدار هر پارامتر را حداکثر ۲۵ نویسه می‌پذیرد و اگر بلندتر باشد کل پیام را
   رد می‌کند؛ برای همین توکن لینک‌های تازه ۲۲ نویسه است و نشانی سایت در متن خود الگو نوشته می‌شود.

   تنظیمات در data/sms.json (کلید API هم؛ چون برای فرستادن کد ورود، پیش از باز شدن کلید داده لازم است).
   می‌توانید کلید را به‌جای آن در inc/config.local.php بنویسید: define('DF_SMSIR_KEY', '...');
   گزارش پیامک‌ها (شماره‌ها) رمزشده نوشته می‌شود و فقط بعد از ورود خوانده می‌شود. */
declare(strict_types=1);
if (!defined('DF')) { http_response_code(403); exit; }

const DF_SMS_TPLS = [
    'otp'      => ['کد ورود', ['CODE', 'VERIFICATIONCODE']],
    'link'     => ['لینک فایل برای مشتری', ['LINK']],
    'link_pin' => ['لینک فایل همراه رمز', ['LINK', 'PIN']],
    'letter'   => ['لینک نامه برای گیرنده', ['LINK']],
    'contract' => ['لینک امضای قرارداد برای کارمند', ['LINK']],
    'vcode'    => ['رمز دیدن سند با QR اصالت (اگر خالی بماند، الگوی «کد ورود» به کار می‌رود)', ['CODE', 'VERIFICATIONCODE']],
];

function sms_cfg(): array {
    $c = array_merge(['key' => '', 'tpl' => [], 'login' => false, 'test' => false], df_read('sms.json', []));
    if (defined('DF_SMSIR_KEY') && DF_SMSIR_KEY !== '') $c['key'] = DF_SMSIR_KEY;
    return $c;
}
function sms_ready(): bool { $c = sms_cfg(); return $c['test'] || trim((string)$c['key']) !== ''; }
function sms_tpl_id(string $k): int { return (int)(sms_cfg()['tpl'][$k] ?? 0); }
function sms_mobile(string $m): string {
    $m = preg_replace('/\D+/', '', df_fa_digits($m));
    if (preg_match('/^(?:0098|98)?0?(9\d{9})$/', (string)$m, $x)) return '0' . $x[1];
    return '';
}
/* پارامترهای پیامکِ کد — مثل وبی (includes/sms.php ‎otp_webotp_suffix‎):
   CODE = خودِ کد، VERIFICATIONCODE = «#کد» برای خطِ آخرِ «@دامنه #VERIFICATIONCODE#» (WebOTP ِ اندروید).
   علامتِ # در متنِ الگو کنارِ پارامتر نمی‌نشیند (sms.ir آن را جزوِ نامِ پارامتر می‌خواند و پیامک «@دامنه 12345» می‌شد)،
   پس جزوِ مقدار است. */
function sms_code_params(string $code): array { return ['CODE' => $code, 'VERIFICATIONCODE' => '#' . $code]; }
/** کد را می‌فرستد؛ اگر الگوی قدیمیِ کاربر VERIFICATIONCODE نداشت و sms.ir رد کرد، فقط با CODE دوباره */
function sms_send_code(string $mobile, string $tpl, string $code, string $note): array {
    $r = sms_send($mobile, $tpl, sms_code_params($code), $note);
    if (!$r['ok'] && empty($r['test']) && !preg_match('/موبایل|کلید|curl|ارتباط|شناسه‌ی الگوی/u', $r['msg'])) {
        $r2 = sms_send($mobile, $tpl, ['CODE' => $code], $note . ' (بی VERIFICATIONCODE)');
        if ($r2['ok']) return $r2;
    }
    return $r;
}
function sms_mask(string $m): string { return strlen($m) === 11 ? substr($m, 0, 4) . '***' . substr($m, -4) : $m; }

/* یک سطر رمزشده در گزارش پیامک (با همان کلید عمومی گزارش لینک‌ها) */
function sms_log(array $rec): void {
    try {
        $json = json_encode(['t' => time()] + $rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $pk = df_keys()['lpk'] ?? '';
        if (!$pk || !function_exists('sodium_crypto_box_seal')) return; /* بدون رمزنگاری، شماره‌ها را نمی‌نویسیم */
        $f = df_path('sms.log');
        @file_put_contents($f, 'S:' . base64_encode(sodium_crypto_box_seal($json, base64_decode($pk))) . "\n", FILE_APPEND | LOCK_EX);
        @chmod($f, 0600);
    } catch (Throwable $e) { error_log('daftar-factor sms log: ' . $e->getMessage()); }
}
function sms_log_read(string $dek, int $limit = 200): array {
    $f = df_path('sms.log'); if (!is_file($f)) return [];
    $k = df_keys(); if (empty($k['lsk']) || !function_exists('sodium_crypto_box_seal_open')) return [];
    $s = df_dec((string)base64_decode($k['lsk']), $dek, 'logkey'); if (!$s) return [];
    $kp = sodium_crypto_box_keypair_from_secretkey_and_publickey($s, base64_decode($k['lpk']));
    $lines = array_slice(file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [], -$limit);
    $out = [];
    foreach (array_reverse($lines) as $l) {
        if (strncmp($l, 'S:', 2) !== 0) continue;
        $j = sodium_crypto_box_seal_open((string)base64_decode(substr($l, 2)), $kp);
        $r = $j ? json_decode($j, true) : null;
        if (is_array($r)) $out[] = $r;
    }
    return $out;
}

/** @return array{ok:bool,msg:string,test?:bool} */
function sms_send(string $mobile, string $tplKey, array $params, string $note = ''): array {
    $m = sms_mobile($mobile);
    $c = sms_cfg();
    $id = (int)($c['tpl'][$tplKey] ?? 0);
    $title = DF_SMS_TPLS[$tplKey][0] ?? $tplKey;
    $res = function (bool $ok, string $msg, bool $test = false) use ($m, $tplKey, $note) {
        sms_log(['to' => $m, 'tpl' => $tplKey, 'ok' => $ok, 'msg' => $msg, 'note' => $note, 'test' => $test]);
        return ['ok' => $ok, 'msg' => $msg, 'test' => $test];
    };
    if ($m === '') return $res(false, 'شماره‌ی موبایل درست نیست (مثلاً ۰۹۱۲۱۲۳۴۵۶۷).');
    foreach ($params as $k => $v) if (mb_strlen((string)$v) > 25) return $res(false, "مقدار پارامتر $k بیش از ۲۵ نویسه است و sms.ir آن را نمی‌پذیرد.");
    if (!empty($c['test'])) return $res(true, 'حالت آزمایشی — پیامک واقعاً فرستاده نشد.', true);
    if ($id <= 0) return $res(false, "شناسه‌ی الگوی «{$title}» در تنظیمات پیامک ثبت نشده است.");
    $key = trim((string)$c['key']);
    if ($key === '') return $res(false, 'کلید API پنل sms.ir ثبت نشده است.');
    if (!function_exists('curl_init')) return $res(false, 'افزونه‌ی curl در PHP فعال نیست.');
    $payload = ['mobile' => $m, 'templateId' => $id, 'parameters' => array_map(fn($k, $v) => ['name' => (string)$k, 'value' => (string)$v], array_keys($params), array_values($params))];
    $ch = curl_init('https://api.sms.ir/v1/send/verify');
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_POST => true, CURLOPT_POSTFIELDS => json_encode($payload, JSON_UNESCAPED_UNICODE),
        CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Accept: application/json', 'x-api-key: ' . $key, 'Expect:'],
        CURLOPT_CONNECTTIMEOUT => 6, CURLOPT_TIMEOUT => 12, CURLOPT_SSL_VERIFYPEER => true]);
    $raw = curl_exec($ch); $err = curl_error($ch); curl_close($ch);
    if ($raw === false) return $res(false, 'ارتباط با sms.ir برقرار نشد: ' . $err);
    $d = json_decode((string)$raw, true);
    $ok = (int)($d['status'] ?? 0) === 1;
    return $res($ok, (string)($d['message'] ?? ($ok ? 'ارسال شد' : 'پاسخ نامعتبر از sms.ir')));
}

/* ---------- کد ورود پیامکی ---------- */
/** @return array{ok:bool,msg:string,show?:string} */
function sms_otp_send(string $user): array {
    $c = sms_cfg();
    $generic = 'اگر ورود با پیامک برای این کاربر و همین دستگاه فعال باشد، کد فرستاده شد.';
    if (empty($c['login'])) return ['ok' => false, 'msg' => 'ورود با پیامک خاموش است.'];
    $u = df_users()[$user] ?? null;
    $mobile = sms_mobile((string)($u['mobile'] ?? ''));
    $did = df_dev_id();
    if (!$u || $mobile === '' || $did === '' || empty($u['devs'][$did]['sms'])) {
        /* این دستگاه برای این کاربر فعال نیست: کد فرستاده نمی‌شود (پیام عمداً کلی است). دلیل در «گزارش پیامک» مدیر ثبت می‌شود. */
        sms_log(['to' => $mobile, 'tpl' => 'otp', 'ok' => false, 'note' => 'کد ورود ' . $user, 'msg' => 'فرستاده نشد: '
            . (!$u ? 'چنین کاربری نیست.' : ($mobile === '' ? 'برای این کاربر شماره‌ی موبایل ثبت نشده است (تنظیمات عمومی ← کاربران).'
            : 'ورود پیامکی روی این دستگاه روشن نیست؛ کاربر یک بار روی همین دستگاه با رمز وارد شود.'))]);
        if (!is_array($_SESSION['otp'] ?? null) || ($_SESSION['otp']['u'] ?? '') !== $user) $_SESSION['otp'] = ['u' => $user, 'hs' => [], 'exp' => time() + 120, 'tries' => 0];
        return ['ok' => true, 'msg' => $generic . ' (اگر نیامد: یک بار با رمز وارد شوید و در «تنظیمات عمومی ← حساب کاربری» ورود با پیامک را برای همین دستگاه روشن کنید.)'];
    }
    $last = (int)(df_read('otp.json', [])[$user] ?? 0);
    if ($last > time() - 60) return ['ok' => false, 'msg' => 'کد قبلی همین الان فرستاده شد؛ ' . df_fa_num((string)(60 - (time() - $last))) . ' ثانیه‌ی دیگر دوباره بخواهید.'];
    df_update('otp.json', function (array &$a) use ($user) { foreach ($a as $k => $t) if ($t < time() - 3600) unset($a[$k]); $a[$user] = time(); });
    $code = str_pad((string)random_int(0, 99999), 5, '0', STR_PAD_LEFT);
    /* کدهای قبلیِ همین کاربر تا پایانِ مهلتشان معتبر می‌مانند: اگر کاربر دوباره «فرستادن کد» زد و کدِ پیامکِ اول را
       وارد کرد، «کد درست نیست» نگیرد (پیامک‌ها گاهی جابه‌جا می‌رسند) */
    $o = $_SESSION['otp'] ?? null;
    $hs = is_array($o) && ($o['u'] ?? '') === $user && (int)($o['exp'] ?? 0) > time() ? array_slice(array_values(array_filter((array)($o['hs'] ?? [($o['h'] ?? '')]))), -2) : [];
    $hs[] = password_hash($code, PASSWORD_DEFAULT);
    $_SESSION['otp'] = ['u' => $user, 'hs' => $hs, 'exp' => time() + 300, 'tries' => 0];
    $r = sms_send_code($mobile, 'otp', $code, 'کد ورود ' . $user);
    if (!$r['ok']) return ['ok' => false, 'msg' => 'پیامک فرستاده نشد: ' . $r['msg']];
    return ['ok' => true, 'msg' => 'کد ورود به ' . df_fa_num(sms_mask($mobile)) . ' فرستاده شد.'] + (!empty($r['test']) ? ['show' => $code] : []);
}
/** @return array{0:?string,1:?string} [کاربر، خطا] */
function sms_otp_check(string $code): array {
    $o = $_SESSION['otp'] ?? null;
    if (!is_array($o) || (int)$o['exp'] < time()) { unset($_SESSION['otp']); return [null, 'مهلت کد تمام شده؛ کد تازه بخواهید.']; }
    $code = df_pin_norm($code);
    $_SESSION['otp']['tries'] = (int)$o['tries'] + 1;
    if ($_SESSION['otp']['tries'] > 5) { unset($_SESSION['otp']); return [null, 'تعداد تلاش‌ها زیاد شد؛ کد تازه بخواهید.']; }
    $ok = false;
    foreach ((array)($o['hs'] ?? [($o['h'] ?? '')]) as $h) if ($h !== '' && password_verify($code, (string)$h)) { $ok = true; break; }
    if (!$ok) { df_login_attempt((string)$o['u'], false); return [null, 'کد درست نیست.' . ($code === '' ? '' : ' (اگر چند بار «فرستادن کد» زده‌اید، کدِ آخرین پیامک را بنویسید.)')]; }
    unset($_SESSION['otp']);
    return [(string)$o['u'], null];
}
