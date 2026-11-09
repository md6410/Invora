<?php
/* دفتر فاکتور — صفحهٔ عمومیِ تأیید اصالت سند (مقصد QR چاپ‌شده روی سند)
   - با باز شدن صفحه، رمزی یک‌بارمصرف به موبایلِ «رابطِ» همان سند پیامک می‌شود؛ صفحه نام رابط و بخشی از
     شماره را نشان می‌دهد تا اسکن‌کننده بداند رمز را از چه کسی بگیرد.
   - تا رمز درست زده نشود، هیچ چیزی از محتوای سند نمایش داده نمی‌شود.
   - سند با کلیدی ساخته‌شده از توکنِ QR رمز شده است (inc/verify.php). */
declare(strict_types=1);
define('DF', 1);
require __DIR__ . '/inc/lib.php';

$nonce = base64_encode(random_bytes(16));
df_headers('share', $nonce);
df_session_start();

function vf_msg(string $msg, int $code = 200, string $title = 'تأیید اصالت سند'): void {
    http_response_code($code);
    df_page($title, '<h1>' . df_h($title) . '</h1><div class="err">' . df_h($msg) . '</div>', '', true);
    exit;
}

$t = (string)($_GET['t'] ?? '');
if (!vf_valid_token($t)) vf_msg('این کد معتبر نیست؛ این سند در سامانه ثبت نشده است.', 404);
$h = vf_hash($t);
$r = vf_all()[$h] ?? null;
if (!$r || !is_file(vf_file($h))) vf_msg('این کد در سامانه پیدا نشد؛ اصالت این سند تأیید نمی‌شود.', 404);
if (!empty($r['dead'])) { df_share_log($h, 'vf_dead'); vf_msg('این سند در سامانهٔ صادرکننده حذف یا باطل شده است و معتبر نیست.', 410); }
$c = vf_contact($r, $t);
$dev = $_SESSION['shdev'][$h] ?? [];
$passOk = isset($_SESSION['vfok'][$h]) && time() - (int)$_SESSION['vfok'][$h] < DF_VF_PASS_MINUTES * 60;
$err = ''; $info = ''; $testCode = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$passOk) {
    $devIn = json_decode((string)($_POST['dev'] ?? ''), true);
    if (is_array($devIn)) {
        $clean = [];
        foreach ($devIn as $k => $v) if (preg_match('/^[a-zA-Z]{1,20}$/', (string)$k) && is_scalar($v)) $clean['d_' . $k] = mb_substr((string)$v, 0, 200);
        $dev = array_slice($clean, 0, 30); $_SESSION['shdev'][$h] = $dev;
    }
    $act = (string)($_POST['act'] ?? '');
    if (!df_csrf_ok((string)($_POST['csrf'] ?? ''))) {
        $err = empty($_COOKIE[session_name()])
            ? 'این مرورگر کوکی را نمی‌پذیرد، برای همین رمز ثبت نمی‌شود. صفحه را در مرورگر اصلی گوشی (Chrome، Safari…) باز کنید.'
            : 'مهلت صفحه تمام شده بود؛ دوباره امتحان کنید.';
    } elseif ($act === 'send') {
        [$ok, $m, $testCode] = vf_send_code($h, $t, $dev);
        if ($ok) $info = $m; else $err = $m;
    } elseif ($act === 'pin') {
        $ip = df_ip();
        $fails = df_read('share-ip.json', []);
        if (count(array_filter($fails[$ip] ?? [], fn($x) => $x > time() - 3600)) >= DF_SHARE_IP_MAX_FAILS_PER_HOUR) vf_msg('تعداد تلاش‌های ناموفق از این اینترنت زیاد است؛ یک ساعت دیگر امتحان کنید.', 429);
        $pin = df_pin_norm((string)($_POST['pin'] ?? ''));
        $o = $_SESSION['vf'][$h] ?? null;
        if (!preg_match('/^\d{5}$/', $pin)) $err = 'رمز ۵ رقمی را کامل وارد کنید.';
        elseif (!is_array($o) || (int)$o['exp'] < time()) { unset($_SESSION['vf'][$h]['h']); $err = 'رمزی برای این مرورگر فرستاده نشده یا مهلتش تمام شده؛ «فرستادن رمز» را بزنید.'; }
        elseif ((int)$o['tries'] >= 5) $err = 'رمز ۵ بار اشتباه زده شد؛ رمز تازه بخواهید.';
        elseif (!password_verify($pin, (string)$o['h'])) {
            $_SESSION['vf'][$h]['tries'] = (int)$o['tries'] + 1;
            df_update('share-ip.json', function (array &$a) use ($ip) {
                foreach ($a as $k => $v) { $a[$k] = array_values(array_filter($v, fn($x) => $x > time() - 3600)); if (!$a[$k]) unset($a[$k]); }
                $a[$ip][] = time();
            });
            df_share_log($h, 'vf_bad', $dev);
            $left = 5 - (int)$_SESSION['vf'][$h]['tries'];
            $err = $left > 0 ? 'رمز اشتباه است. ' . df_fa_num((string)$left) . ' بار دیگر می‌توانید امتحان کنید.' : 'رمز ۵ بار اشتباه زده شد؛ رمز تازه بخواهید.';
        } else {
            unset($_SESSION['vf'][$h]);
            $_SESSION['vfok'][$h] = time();
            df_share_log($h, 'vf_ok', $dev);
            header('Location: v.php?t=' . $t); exit;
        }
    }
}

if (!$passOk) {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') df_share_log($h, 'vf_open');
    $who = $c['m'] === '' ? '' : ($c['n'] !== '' ? '<b>' . df_h($c['n']) . '</b>' : 'رابطِ این سند') . ' به شمارهٔ <b dir="ltr" style="unicode-bidi:isolate">' . df_h(df_fa_num(sms_mask($c['m']))) . '</b>';
    $sent = !empty($_SESSION['vf'][$h]['h']) && (int)($_SESSION['vf'][$h]['exp'] ?? 0) > time();
    $csrf = df_h(df_csrf());
    $devJs = '(function(){var d={};try{var n=navigator,s=screen;d.scr=s.width+"x"+s.height;d.dpr=window.devicePixelRatio;d.tz=Intl.DateTimeFormat().resolvedOptions().timeZone;d.langs=(n.languages||[n.language]).join(",");d.plat=n.platform;d.touch=n.maxTouchPoints;}catch(e){}'
        . 'var v=JSON.stringify(d);Array.prototype.forEach.call(document.querySelectorAll("input[name=dev]"),function(i){i.value=v});'
        . ($c['m'] !== '' && !$sent && $_SERVER['REQUEST_METHOD'] !== 'POST' ? 'var f=document.getElementById("sf");if(f&&!sessionStorage.getItem("vfs' . substr($h, 0, 12) . '")){sessionStorage.setItem("vfs' . substr($h, 0, 12) . '","1");f.submit()}' : '')
        . '})();';
    $body = '<h1>تأیید اصالت سند</h1>'
        . '<p style="margin:0">این کد در سامانهٔ صادرکنندهٔ سند ثبت شده است. برای دیدنِ خودِ سند و مقایسه با نسخه‌ای که در دست دارید، رمزِ پیامک‌شده را وارد کنید.</p>'
        . ($err ? '<div class="err">' . df_h($err) . '</div>' : '')
        . ($info ? '<div class="ok" style="background:#e6f2ea;border-radius:8px;padding:6px 10px;font-size:13.5px">' . df_h($info) . '</div>' : '')
        . ($testCode !== '' ? '<div class="muted">حالت آزمایشیِ پیامک: رمز ' . df_h(df_fa_num($testCode)) . '</div>' : '');
    if ($c['m'] === '') {
        $body .= '<div class="err">برای این سند رابطی با شمارهٔ موبایل ثبت نشده است؛ برای دیدن سند با صادرکنندهٔ آن تماس بگیرید.</div>';
    } else {
        $body .= '<p style="margin:0">رمز به ' . $who . ' پیامک ' . ($sent || $info ? 'شد' : 'می‌شود') . '. رمز را از ایشان بگیرید.</p>'
            . '<form method="post" autocomplete="off" style="display:flex;flex-direction:column;gap:10px"><input type="hidden" name="csrf" value="' . $csrf . '"><input type="hidden" name="act" value="pin"><input type="hidden" name="dev" value="">'
            . '<label>رمز ۵ رقمی<input class="pin" name="pin" type="text" inputmode="numeric" maxlength="24" autocomplete="one-time-code" required' . ($sent || $info ? ' autofocus' : '') . '></label><button>دیدن سند</button></form>'
            . '<form id="sf" method="post"><input type="hidden" name="csrf" value="' . $csrf . '"><input type="hidden" name="act" value="send"><input type="hidden" name="dev" value="">'
            . '<button style="background:transparent;color:#1e5a55;border:1px solid #1e5a55;width:100%">' . ($sent || $info ? 'فرستادن دوبارهٔ رمز' : 'فرستادن رمز') . '</button></form>'
            . '<p class="muted" style="margin:0">رمز ' . df_fa_num((string)DF_VF_CODE_MINUTES) . ' دقیقه اعتبار دارد. هر اسکن و هر بار دیدن سند با آی‌پی و مشخصات دستگاه ثبت می‌شود.</p>';
    }
    df_page('تأیید اصالت سند', $body . '<script nonce="' . $nonce . '">' . $devJs . '</script>', '', true);
    exit;
}

$html = df_dec((string)file_get_contents(vf_file($h)), vf_key($t), 'verify');
if ($html === null) vf_msg('سند باز نشد. به صادرکنندهٔ سند خبر دهید.', 500);
df_share_log($h, 'vf_view', $dev);
$html = preg_replace('~<script\b[^>]*>.*?</script>~is', '', $html);
$when = !empty($r['upd']) ? df_fa_num(jdate_vf((int)$r['upd'])) : '';
$bar = '<div class="bar" style="background:#e6f2ea;border-bottom:2px solid #2c7149"><b style="color:#2c7149">✓ این سند در سامانهٔ صادرکننده ثبت شده و اصل است' . ($when ? ' <small style="font-weight:400;color:#555">— آخرین به‌روزرسانی ' . df_h($when) . '</small>' : '') . '</b><span><button id="df-print">چاپ / ذخیرهٔ PDF</button></span></div>'
    . '<script nonce="' . $nonce . '">document.getElementById("df-print").addEventListener("click",function(){window.print()});</script>';
$html = preg_replace('~<div class="bar">.*?</div>~s', '', $html, 1);
$html = preg_replace('~<body>~', '<body>' . $bar, $html, 1);
header('Content-Type: text/html; charset=utf-8');
echo $html;

function jdate_vf(int $ts): string {
    [$gy, $gm, $gd] = array_map('intval', explode('-', date('Y-m-d', $ts)));
    $g_d_m = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    $gy2 = $gm > 2 ? $gy + 1 : $gy;
    $days = 355666 + 365 * $gy + intdiv($gy2 + 3, 4) - intdiv($gy2 + 99, 100) + intdiv($gy2 + 399, 400) + $gd + $g_d_m[$gm - 1];
    $jy = -1595 + 33 * intdiv($days, 12053); $days %= 12053;
    $jy += 4 * intdiv($days, 1461); $days %= 1461;
    if ($days > 365) { $jy += intdiv($days - 1, 365); $days = ($days - 1) % 365; }
    $jm = $days < 186 ? 1 + intdiv($days, 31) : 7 + intdiv($days - 186, 30);
    $jd = 1 + ($days < 186 ? $days % 31 : ($days - 186) % 30);
    return sprintf('%04d/%02d/%02d', $jy, $jm, $jd) . ' ساعت ' . date('H:i', $ts);
}
