<?php
/* دفتر فاکتور — صفحه‌ی عمومی دریافت فاکتورِ اشتراک‌گذاری‌شده (با رمز)
   - فایل روی سرور رمزشده است؛ کلیدش از توکن لینک و رمز ساخته می‌شود و روی سرور نیست.
   - تا رمز درست وارد نشود، صفحه هیچ نشانی از نام، نوع یا فرستنده‌ی فایل ندارد (حتی در عنوان و پیش‌نمایش لینک).
   - رمزِ ناقص تلاش اشتباه حساب نمی‌شود؛ فاصله، «رمز:» و نشانه‌های نامرئیِ کپی از رمز حذف می‌شوند.
   - هر باز شدن، رمز درست یا اشتباه، دیدن و دانلود، با آی‌پی و مشخصات دستگاه ثبت می‌شود.
   - بعد از ۵ رمز اشتباه فقط لینک غیرفعال می‌شود؛ فایل و گزارش‌ها می‌مانند. */
declare(strict_types=1);
define('DF', 1);
require __DIR__ . '/inc/lib.php';

$nonce = base64_encode(random_bytes(16));
df_headers('share', $nonce);
header('Accept-CH: Sec-CH-UA-Model, Sec-CH-UA-Platform-Version, Sec-CH-UA-Full-Version-List, Sec-CH-UA-Arch, Sec-CH-UA-Bitness, Device-Memory');
header('Critical-CH: Sec-CH-UA-Model, Sec-CH-UA-Platform-Version');
df_session_start();

function share_msg(string $msg, int $code = 200): void {
    http_response_code($code);
    df_page('دریافت فایل', '<h1>دریافت فایل</h1><div class="err">' . df_h($msg) . '</div>', '', true);
    exit;
}
const DEAD_MSG = ['locked' => 'این لینک به دلیل ۵ بار وارد کردن رمز اشتباه غیرفعال شده است. از فرستنده لینک تازه بخواهید.',
                  'revoked' => 'این لینک توسط فرستنده غیرفعال شده است.'];

$t = (string)($_GET['t'] ?? '');
if (!preg_match('/^([a-f0-9]{32}|[A-Za-z0-9_-]{22})$/', $t)) share_msg('لینک نامعتبر است.', 404);
$h = df_share_hash($t);
$s = df_read('shares.json', [])[$h] ?? null;
if (!$s || !is_file(df_share_file($h))) share_msg('این لینک وجود ندارد.', 404);
$title = (string)(df_dec((string)base64_decode((string)($s['tt'] ?? '')), df_share_title_key($t), 'title') ?? '');
$dev = $_SESSION['shdev'][$h] ?? [];

$blocked = function (array $s): ?array {
    if (!empty($s['dead'])) return [DEAD_MSG[$s['dead']] ?? 'این لینک غیرفعال است.', 'dead_' . $s['dead']];
    if (($s['exp'] ?? 0) > 0 && time() > $s['exp']) return ['اعتبار این لینک تمام شده است.', 'expired'];
    return null;
};

$passOk = isset($_SESSION['sh'][$h]) && time() - (int)$_SESSION['sh'][$h] < DF_SHARE_PASS_MINUTES * 60 && df_sess_get('sf:' . $h) !== null;
/* a revoked, locked or expired link stops at once, even for someone who already entered the PIN (files keep streaming otherwise) */
if ($b = $blocked($s)) { if (!$passOk || !isset($_GET['f'])) df_share_log($h, 'blocked', ['why' => $b[1]] + $dev); if (isset($_GET['f'])) { http_response_code(410); exit; } share_msg($b[0], 410); }
$err = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && !$passOk) {
    $devIn = json_decode((string)($_POST['dev'] ?? ''), true);
    if (is_array($devIn)) {
        $clean = [];
        foreach ($devIn as $k => $v) if (preg_match('/^[a-zA-Z]{1,20}$/', (string)$k) && (is_scalar($v))) $clean['d_' . $k] = mb_substr((string)$v, 0, 200);
        $dev = array_slice($clean, 0, 30);
        $_SESSION['shdev'][$h] = $dev;
    }
    if (!df_csrf_ok((string)($_POST['csrf'] ?? ''))) {
        /* without the session cookie the PIN can never be accepted (in-app browsers of some messengers block cookies) */
        $err = empty($_COOKIE[session_name()])
            ? 'این مرورگر کوکی را نمی‌پذیرد، برای همین رمز ثبت نمی‌شود. لینک را در مرورگر اصلی گوشی یا رایانه (Chrome، Safari، Edge…) باز کنید. این تلاش اشتباه حساب نشد.'
            : 'مهلت صفحه تمام شده بود؛ دوباره رمز را وارد کنید. این تلاش اشتباه حساب نشد.';
    } else {
        $ip = df_ip();
        $ipFails = df_read('share-ip.json', []);
        $recent = array_filter($ipFails[$ip] ?? [], fn($x) => $x > time() - 3600);
        if (count($recent) >= DF_SHARE_IP_MAX_FAILS_PER_HOUR) { df_share_log($h, 'ip_limited', $dev); share_msg('تعداد تلاش‌های ناموفق از این اینترنت زیاد است؛ یک ساعت دیگر امتحان کنید.', 429); }
        $pin = df_pin_norm((string)($_POST['pin'] ?? ''));
        /* an incomplete PIN is not an attempt: ask again without using up one of the 5 tries */
        $res = !preg_match('/^\d{4,5}$/', $pin) ? 'short' : df_update('shares.json', function (array &$all) use ($h, $pin) {
            if (!isset($all[$h])) return 'gone';
            $x = &$all[$h];
            if (!empty($x['dead'])) return 'dead';
            if (($x['exp'] ?? 0) > 0 && time() > $x['exp']) return 'expired';
            if (($x['max'] ?? 0) > 0 && ($x['used'] ?? 0) >= $x['max']) return 'used';
            if (password_verify($pin, (string)($x['pin'] ?? ''))) { $x['used']++; $x['last'] = time(); return 'ok:' . $x['used']; }
            $x['fails'] = ($x['fails'] ?? 0) + 1;
            if ($x['fails'] >= 5) { $x['dead'] = 'locked'; $x['deadAt'] = time(); return 'locked'; }
            return 'bad:' . (5 - $x['fails']);
        });
        if (strncmp($res, 'ok:', 3) === 0) {
            $key = df_share_file_key($t, $pin, (int)($s['pk'] ?? 1));
            if (df_dec((string)file_get_contents(df_share_file($h)), $key, 'share') === null) { df_share_log($h, 'error', $dev); share_msg('فایل باز نشد. به فرستنده خبر دهید.', 500); }
            df_sess_put('sf:' . $h, $key);
            $_SESSION['sh'][$h] = time();
            df_share_log($h, 'pin_ok', ['n' => (int)substr($res, 3)] + $dev);
            header('Location: d.php?t=' . $t); exit;
        }
        if (strncmp($res, 'bad:', 4) === 0 || $res === 'locked') {
            df_update('share-ip.json', function (array &$a) use ($ip) {
                foreach ($a as $k => $v) { $a[$k] = array_values(array_filter($v, fn($x) => $x > time() - 3600)); if (!$a[$k]) unset($a[$k]); }
                $a[$ip][] = time();
            });
        }
        if ($res === 'locked') { df_share_log($h, 'pin_bad', ['left' => 0] + $dev); df_share_log($h, 'locked', $dev); share_msg(DEAD_MSG['locked'], 410); }
        if ($res === 'used') { df_share_log($h, 'blocked', ['why' => 'exhausted'] + $dev); share_msg('تعداد دفعات مجاز دریافت این لینک تمام شده است.', 410); }
        if ($res === 'short') $err = 'رمز کامل نیست؛ رمز ' . df_fa_num('5') . ' رقمی (یا ' . df_fa_num('4') . ' رقمی) را وارد کنید. این تلاش اشتباه حساب نشد.';
        elseif (strncmp($res, 'bad:', 4) !== 0) { df_share_log($h, 'blocked', ['why' => $res] + $dev); share_msg('این لینک دیگر فعال نیست.', 410); }
        else {
            df_share_log($h, 'pin_bad', ['left' => (int)substr($res, 4)] + $dev);
            $err = 'رمز اشتباه است. ' . df_fa_num(substr($res, 4)) . ' بار دیگر می‌توانید امتحان کنید؛ بعد از آن لینک غیرفعال می‌شود.';
        }
    }
}

if (!$passOk) {
    if (($s['max'] ?? 0) > 0 && ($s['used'] ?? 0) >= $s['max']) { df_share_log($h, 'blocked', ['why' => 'exhausted'] + $dev); share_msg('تعداد دفعات مجاز دریافت این لینک تمام شده است.', 410); }
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') df_share_log($h, 'open');
    $left = 5 - (int)(df_read('shares.json', [])[$h]['fails'] ?? 0);
    /* collects device details (screen, time zone, language, model…) and sends them with the PIN */
    $js = '<script nonce="' . $nonce . '">(function(){var f=document.getElementById("pf"),d={};try{var n=navigator,s=screen;d.scr=s.width+"x"+s.height;d.dpr=window.devicePixelRatio;d.vp=innerWidth+"x"+innerHeight;d.depth=s.colorDepth;'
        . 'd.tz=Intl.DateTimeFormat().resolvedOptions().timeZone;d.tzo=new Date().getTimezoneOffset();d.langs=(n.languages||[n.language]).join(",");d.plat=n.platform;d.cores=n.hardwareConcurrency;d.mem=n.deviceMemory;d.touch=n.maxTouchPoints;'
        . 'var c=n.connection;if(c){d.net=c.effectiveType;d.dl=c.downlink}d.cookies=n.cookieEnabled;d.orient=(s.orientation||{}).type;}catch(e){}'
        . 'function put(){f.dev.value=JSON.stringify(d)}put();try{if(navigator.userAgentData&&navigator.userAgentData.getHighEntropyValues){navigator.userAgentData.getHighEntropyValues(["model","platformVersion","fullVersionList","architecture"]).then(function(v){d.model=v.model;d.platform=v.platform;d.platformVer=v.platformVersion;d.mobile=v.mobile;d.arch=v.architecture;d.brands=(v.fullVersionList||[]).map(function(b){return b.brand+" "+b.version}).join(", ");put()})}}catch(e){}})();</script>';
    df_page('دریافت فایل', '<h1>دریافت فایل</h1><p>این فایل با رمز محافظت شده است.</p>'
        . ($err ? '<div class="err">' . df_h($err) . '</div>' : '')
        . '<form id="pf" method="post" autocomplete="off" style="display:flex;flex-direction:column;gap:10px"><input type="hidden" name="csrf" value="' . df_h(df_csrf()) . '"><input type="hidden" name="dev" value="">'
        . '<label>رمز را وارد کنید<input class="pin" name="pin" type="text" inputmode="numeric" maxlength="24" autocomplete="one-time-code" autocorrect="off" autocapitalize="off" spellcheck="false" required autofocus></label><button>باز کردن</button></form>'
        . '<p class="muted">رمز را از فرستنده بگیرید. ' . df_fa_num((string)max(0, $left)) . ' بار فرصت دارید؛ بعد از ۵ بار رمز اشتباه، لینک غیرفعال می‌شود.'
        . (($s['exp'] ?? 0) > 0 ? ' اعتبار این لینک تا ' . df_h(df_fa_num(jdate_str((int)$s['exp']))) . ' است.' : '') . '</p>' . $js, '', true);
    exit;
}

$html = df_dec((string)file_get_contents(df_share_file($h)), (string)df_sess_get('sf:' . $h), 'share');
if ($html === null) share_msg('فایل باز نشد.', 500);
if (($s['kind'] ?? '') === 'media') { media_page($h, $t, $html, $dev, $nonce); exit; }
$html = preg_replace('~<script\b[^>]*>.*?</script>~is', '', $html);
$name = preg_replace('~[\\\\/:*?"<>|\x00-\x1f]+~u', '-', $title ?: 'فاکتور') . '.html';
if (isset($_GET['dl'])) {
    df_share_log($h, 'download', $dev);
    header('Content-Type: text/html; charset=utf-8');
    header("Content-Disposition: attachment; filename=\"invoice.html\"; filename*=UTF-8''" . rawurlencode($name));
    echo $html;
    exit;
}
df_share_log($h, 'view', $dev);
$bar = '<div class="bar"><b>' . df_h($title) . '</b><span style="display:flex;gap:8px"><a href="d.php?t=' . $t . '&amp;dl=1" style="padding:6px 16px;border-radius:8px;border:1px solid #1e5a55;color:#1e5a55;text-decoration:none">دانلود فایل</a><button id="df-print">چاپ / ذخیره‌ی PDF</button></span></div>'
    . '<script nonce="' . $nonce . '">document.getElementById("df-print").addEventListener("click",function(){window.print()});</script>';
$html = preg_replace('~<div class="bar">.*?</div>~s', '', $html, 1);
$html = preg_replace('~<body>~', '<body>' . $bar, $html, 1);
header('Content-Type: text/html; charset=utf-8');
echo $html;

/* لینکِ کاتالوگ و گالری: صفحه‌ی فایل‌ها، یا پخش/دانلود یکی از آن‌ها (با Range) */
function media_page(string $h, string $t, string $plain, array $dev, string $nonce): void {
    $pack = json_decode($plain, true);
    $items = is_array($pack['items'] ?? null) ? $pack['items'] : [];
    if (isset($_GET['f'])) {
        $n = (int)$_GET['f']; $it = $items[$n] ?? null;
        if (!$it || !gal_valid_id((string)$it['id']) || !isset(gal_items()[$it['id']])) { http_response_code(404); header('Content-Type: text/plain; charset=utf-8'); exit('این فایل دیگر در دسترس نیست.'); }
        $thumb = isset($_GET['thumb']); $dl = isset($_GET['dl']);
        $r = (string)($_SERVER['HTTP_RANGE'] ?? '');
        if (!$thumb && ($r === '' || preg_match('/^bytes=0-/', $r))) df_share_log($h, $dl ? 'download' : 'media', ['item' => (string)$it['name']] + $dev);
        gal_stream((string)$it['id'], (string)base64_decode((string)$it['k']), (string)$it['type'], (string)$it['name'], $dl, $thumb);
    }
    df_share_log($h, 'view', $dev);
    $u = fn(int $n, string $q = '') => 'd.php?t=' . rawurlencode($t) . '&amp;f=' . $n . $q;
    $cards = '';
    foreach ($items as $n => $it) {
        $type = (string)$it['type']; $name = df_h((string)($it['title'] ?: $it['name']));
        $desc = trim((string)($it['desc'] ?? '')) !== '' ? '<p class="d">' . nl2br(df_h((string)$it['desc'])) . '</p>' : '';
        $meta = '<small>' . df_h((string)$it['name']) . ' · ' . gal_fmt_size((int)$it['size']) . '</small>';
        $dlb = '<a class="b" href="' . $u($n, '&amp;dl=1') . '">دانلود</a>';
        if (preg_match('~^image/(jpeg|png|gif|webp|avif|bmp)$~', $type)) {
            $cards .= '<figure class="c"><a href="' . $u($n) . '" target="_blank" rel="noopener"><img loading="lazy" src="' . $u($n, !empty($it['thumb']) ? '&amp;thumb=1' : '') . '" alt=""></a><figcaption><b>' . $name . '</b>' . $desc . $meta . '<span class="bs"><a class="b" href="' . $u($n) . '" target="_blank" rel="noopener">اندازه‌ی کامل</a>' . $dlb . '</span></figcaption></figure>';
        } elseif (preg_match('~^(video|audio)/~', $type) && gal_inline_type($type)) {
            $tag = strpos($type, 'audio/') === 0 ? 'audio' : 'video';
            $cards .= '<figure class="c"><' . $tag . ' controls preload="metadata" playsinline' . (!empty($it['thumb']) && $tag === 'video' ? ' poster="' . $u($n, '&amp;thumb=1') . '"' : '') . ' src="' . $u($n) . '"></' . $tag . '><figcaption><b>' . $name . '</b>' . $desc . $meta . '<span class="bs">' . $dlb . '</span></figcaption></figure>';
        } else {
            $open = gal_inline_type($type) ? '<a class="b" href="' . $u($n) . '" target="_blank" rel="noopener">باز کردن</a>' : '';
            $cards .= '<figure class="c f">' . (!empty($it['thumb']) ? '<img loading="lazy" src="' . $u($n, '&amp;thumb=1') . '" alt="">' : '<div class="ic">' . df_h(strtoupper(pathinfo((string)$it['name'], PATHINFO_EXTENSION) ?: 'FILE')) . '</div>') . '<figcaption><b>' . $name . '</b>' . $desc . $meta . '<span class="bs">' . $open . $dlb . '</span></figcaption></figure>';
        }
    }
    $info = is_array($pack['info'] ?? null) ? $pack['info'] : null; $head = '';
    if ($info) {
        $rows = '';
        foreach ((array)($info['specs'] ?? []) as $r) $rows .= '<tr><th>' . df_h((string)($r[0] ?? '')) . '</th><td>' . nl2br(df_h((string)($r[1] ?? ''))) . '</td></tr>';
        $head = '<div class="pi">' . (preg_match('~^data:image/(jpeg|png|webp);base64,~', (string)($info['img'] ?? '')) ? '<img class="pim" src="' . df_h((string)$info['img']) . '" alt="">' : '')
            . '<div class="pt"><h1>' . df_h((string)($info['name'] ?: ($pack['title'] ?? ''))) . '</h1>'
            . ((string)($info['price'] ?? '') !== '' ? '<div class="pr">' . df_h((string)$info['price']) . '</div>' : '')
            . ((string)($info['about'] ?? '') !== '' ? '<p>' . nl2br(df_h((string)$info['about'])) . '</p>' : '')
            . ($rows ? '<table class="sp">' . $rows . '</table>' : '') . '</div></div>';
    }
    header('Content-Type: text/html; charset=utf-8');
    echo '<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>' . df_h((string)($pack['title'] ?? 'فایل‌ها')) . '</title>'
        . '<style>:root{color-scheme:light dark}*{box-sizing:border-box}body{margin:0;background:#eef0ee;color:#1d2321;font:15px/1.8 Vazirmatn,Tahoma,sans-serif;padding:16px}'
        . '@media (prefers-color-scheme:dark){body{background:#121615;color:#e4e8e6}.c{background:#1a1f1e!important;border-color:#2e3533!important}.b{color:#7fd0c2!important;border-color:#7fd0c2!important}}'
        . 'h1{font-size:20px;margin:0 0 4px}.top{max-width:1200px;margin:0 auto 14px}.g{max-width:1200px;margin:auto;display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px}'
        . '.c{margin:0;background:#fff;border:1px solid #d7dbd7;border-radius:12px;overflow:hidden;display:flex;flex-direction:column}.c img,.c video{width:100%;max-height:340px;object-fit:contain;background:#000;display:block}.c audio{width:100%}'
        . '.c.f img{object-fit:cover;background:#f1f3f1}.ic{height:150px;display:grid;place-items:center;font:800 28px system-ui;color:#1e5a55;background:#e1edeb}'
        . 'figcaption{padding:10px 12px;display:flex;flex-direction:column;gap:4px}figcaption small{color:#6b736f}.d{margin:0;font-size:13.5px}.bs{display:flex;gap:8px;flex-wrap:wrap;margin-top:4px}'
        . '.b{font-size:13px;padding:3px 12px;border:1px solid #1e5a55;border-radius:8px;color:#1e5a55;text-decoration:none}'
        . '.pi{max-width:1200px;margin:0 auto 16px;background:#fff;border:1px solid #d7dbd7;border-radius:12px;padding:16px;display:flex;gap:18px;flex-wrap:wrap}.pim{width:220px;max-width:100%;object-fit:contain;border-radius:8px;align-self:flex-start}.pt{flex:1;min-width:240px}.pt p{white-space:normal}'
        . '.pr{font-weight:800;color:#1e5a55;font-size:17px}.sp{border-collapse:collapse;width:100%;margin-top:8px}.sp th,.sp td{border-bottom:1px solid #e3e6e3;padding:6px 8px;text-align:right;vertical-align:top}.sp th{width:34%;color:#555;font-weight:600}'
        . '@media (prefers-color-scheme:dark){.pi{background:#1a1f1e;border-color:#2e3533}.sp th{color:#9aa49f}.sp th,.sp td{border-color:#2e3533}.pr{color:#7fd0c2}}</style></head><body>'
        . $head . '<div class="top">' . ($info ? '' : '<h1>' . df_h((string)($pack['title'] ?? 'فایل‌ها')) . '</h1>') . ($items ? '<small>' . df_fa_num((string)count($items)) . ' فایل</small>' : '') . '</div><div class="g">' . $cards . '</div></body></html>';
}

/* تبدیل زمان یونیکس به تاریخ شمسی برای نمایش */
function jdate_str(int $ts): string {
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
