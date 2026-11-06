<?php
declare(strict_types=1);
if (!defined('DF')) { http_response_code(403); exit; }
require __DIR__ . '/config.php';
date_default_timezone_set('Asia/Tehran');
mb_internal_encoding('UTF-8');

const DF_DOCS_DIR = 'اسناد';
define('DF_TRASH_DIR', 'حذف' . "\u{200C}" . 'شده');
require __DIR__ . '/crypto.php';

/* ---------------- storage ---------------- */
function df_deny_htaccess(): string {
    return "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n";
}
function df_data_dir(): string {
    static $dir = null;
    if ($dir !== null) return $dir;
    $cands = [];
    if (DF_DATA_DIR !== '') $cands[] = rtrim(DF_DATA_DIR, '/');
    else {
        $docRoot = rtrim((string)($_SERVER['DOCUMENT_ROOT'] ?? ''), '/');
        if ($docRoot !== '' && is_dir($docRoot)) {
            $outside = dirname($docRoot) . '/daftar-factor-data';
            if (is_dir($outside) || is_writable(dirname($docRoot))) $cands[] = $outside;
        }
        $cands[] = dirname(__DIR__) . '/data';
    }
    foreach ($cands as $c) {
        if (!is_dir($c)) @mkdir($c, 0700, true);
        if (is_dir($c) && is_writable($c)) { $dir = $c; break; }
    }
    if ($dir === null) { http_response_code(500); exit('Data folder is not writable.'); }
    if (!is_file($dir . '/.htaccess')) @file_put_contents($dir . '/.htaccess', df_deny_htaccess());
    if (!is_file($dir . '/index.html')) @file_put_contents($dir . '/index.html', '');
    return $dir;
}
function df_path(string $rel): string { return df_data_dir() . '/' . $rel; }
function df_read(string $name, $default) {
    $p = df_path($name);
    if (!is_file($p)) return $default;
    $j = json_decode((string)@file_get_contents($p), true);
    return is_array($j) ? $j : $default;
}
function df_write_atomic(string $path, string $content): void {
    $dir = dirname($path);
    if (!is_dir($dir)) @mkdir($dir, 0700, true);
    $tmp = $path . '.tmp' . bin2hex(random_bytes(4));
    if (@file_put_contents($tmp, $content, LOCK_EX) === false) throw new RuntimeException('write failed');
    @chmod($tmp, 0600);
    if (!@rename($tmp, $path)) { @unlink($tmp); throw new RuntimeException('rename failed'); }
}
function df_write(string $name, $data): void {
    df_write_atomic(df_path($name), json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
}
/* read-modify-write with an exclusive lock; $fn receives the data by reference */
function df_update(string $name, callable $fn, $default = []) {
    $lp = df_path('locks');
    if (!is_dir($lp)) @mkdir($lp, 0700, true);
    $lock = fopen($lp . '/' . preg_replace('/[^a-z0-9_.-]/i', '_', $name) . '.lock', 'c');
    flock($lock, LOCK_EX);
    try {
        $data = df_read($name, $default);
        $res = $fn($data);
        df_write($name, $data);
        return $res;
    } finally { flock($lock, LOCK_UN); fclose($lock); }
}

/* ---------------- request helpers ---------------- */
function df_is_https(): bool {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (string)($_SERVER['SERVER_PORT'] ?? '') === '443'
        || strtolower((string)($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https';
}
function df_base_path(): string {
    $d = str_replace('\\', '/', dirname((string)($_SERVER['SCRIPT_NAME'] ?? '/')));
    return rtrim($d, '/') . '/';
}
function df_base_url(): string {
    $host = (string)($_SERVER['HTTP_HOST'] ?? 'localhost');
    if (!preg_match('/^[a-z0-9.\-:\[\]]+$/i', $host)) $host = 'localhost';
    return (df_is_https() ? 'https' : 'http') . '://' . $host . df_base_path();
}
function df_ip(): string { return (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0'); }
function df_h(?string $s): string { return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'); }
function df_fa_digits(string $s): string {
    return strtr($s, ['۰'=>'0','۱'=>'1','۲'=>'2','۳'=>'3','۴'=>'4','۵'=>'5','۶'=>'6','۷'=>'7','۸'=>'8','۹'=>'9','٠'=>'0','١'=>'1','٢'=>'2','٣'=>'3','٤'=>'4','٥'=>'5','٦'=>'6','٧'=>'7','٨'=>'8','٩'=>'9']);
}
function df_headers(string $kind, string $nonce = ''): void {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    header('Cache-Control: no-store, no-cache, must-revalidate, private');
    header('Pragma: no-cache');
    if (df_is_https()) header('Strict-Transport-Security: max-age=31536000');
    if ($kind === 'app') {
        header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    } elseif ($kind === 'share') {
        header("Content-Security-Policy: default-src 'none'; script-src 'nonce-$nonce'; style-src 'unsafe-inline' https://fonts.googleapis.com; font-src data: https://fonts.gstatic.com; img-src data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
        header('X-Robots-Tag: noindex, nofollow');
    } else {
        header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
    }
}

/* ---------------- sessions & auth ---------------- */
function df_session_start(): void {
    if (session_status() === PHP_SESSION_ACTIVE) return;
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.use_trans_sid', '0');
    ini_set('session.gc_maxlifetime', (string)(DF_MAX_SESSION_HOURS * 3600));
    $sp = df_path('sessions');
    if (!is_dir($sp)) @mkdir($sp, 0700, true);
    if (is_dir($sp) && is_writable($sp)) {
        session_save_path($sp);
        if (random_int(1, 50) === 1) { /* own garbage collection (cPanel often disables PHP's) */
            foreach (glob($sp . '/sess_*') ?: [] as $f) if (@filemtime($f) < time() - DF_MAX_SESSION_HOURS * 3600) @unlink($f);
        }
    }
    session_name('DFSESS');
    session_set_cookie_params(['lifetime' => 0, 'path' => df_base_path(), 'secure' => df_is_https(), 'httponly' => true, 'samesite' => 'Lax']);
    session_start();
}
function df_csrf(): string {
    if (empty($_SESSION['csrf'])) $_SESSION['csrf'] = bin2hex(random_bytes(32));
    return $_SESSION['csrf'];
}
function df_csrf_ok(string $t): bool { return !empty($_SESSION['csrf']) && is_string($t) && hash_equals($_SESSION['csrf'], $t); }

function df_users(): array { $u = df_read('users.json', ['users' => []]); return is_array($u['users'] ?? null) ? $u['users'] : []; }
function df_valid_username(string $u): bool { return (bool)preg_match('/^[A-Za-z0-9_.\-]{3,32}$/', $u); }
function df_password_problem(string $p): ?string {
    if (mb_strlen($p) < 8) return 'رمز عبور باید دست‌کم ۸ نویسه باشد.';
    if (mb_strlen($p) > 200) return 'رمز عبور خیلی طولانی است.';
    return null;
}
function df_user_add(string $u, string $p, bool $admin, ?string $dek): ?string {
    if (!df_valid_username($u)) return 'نام کاربری فقط حروف انگلیسی، عدد، نقطه، خط تیره و زیرخط (۳ تا ۳۲ نویسه) باشد.';
    if ($e = df_password_problem($p)) return $e;
    $wrap = $dek ? df_wrap($dek, $p) : null;
    return df_update('users.json', function (array &$d) use ($u, $p, $admin, $wrap) {
        $d['users'] = $d['users'] ?? [];
        if (isset($d['users'][$u])) return 'این نام کاربری وجود دارد.';
        $d['users'][$u] = ['hash' => password_hash($p, PASSWORD_DEFAULT), 'admin' => $admin, 'created' => time(), 'ver' => 1] + ($wrap ?: []);
        return null;
    }, ['users' => []]);
}
/* set a user's password (and re-lock the data key with it); signs out that user's other sessions */
function df_user_setpass(string $u, string $p, string $dek): ?string {
    if ($e = df_password_problem($p)) return $e;
    $wrap = df_wrap($dek, $p);
    return df_update('users.json', function (array &$d) use ($u, $p, $wrap) {
        if (!isset($d['users'][$u])) return 'کاربر پیدا نشد.';
        $d['users'][$u] = array_merge($d['users'][$u], $wrap, ['hash' => password_hash($p, PASSWORD_DEFAULT), 'ver' => ($d['users'][$u]['ver'] ?? 1) + 1]);
        return null;
    }, ['users' => []]);
}
function df_logged_in(): bool {
    if (empty($_SESSION['u'])) return false;
    $now = time();
    $users = df_users();
    $u = $users[$_SESSION['u']] ?? null;
    if (!$u || ($u['ver'] ?? 1) !== ($_SESSION['ver'] ?? 0)
        || $now - (int)($_SESSION['t'] ?? 0) > DF_IDLE_MINUTES * 60
        || $now - (int)($_SESSION['since'] ?? 0) > DF_MAX_SESSION_HOURS * 3600
        || df_dek() === null) {
        df_logout();
        return false;
    }
    $_SESSION['t'] = $now;
    $_SESSION['admin'] = !empty($u['admin']);
    return true;
}
function df_login_locked(string $user): int {
    $a = df_read('login-attempts.json', []);
    $now = time(); $m = 0;
    foreach (['ip:' . df_ip(), 'u:' . strtolower($user)] as $k) if (!empty($a[$k]['lock']) && $a[$k]['lock'] > $now) $m = max($m, $a[$k]['lock'] - $now);
    return $m;
}
function df_login_attempt(string $user, bool $ok): void {
    df_update('login-attempts.json', function (array &$a) use ($user, $ok) {
        $now = time();
        foreach ($a as $k => $v) if (($v['lock'] ?? 0) < $now && ($v['first'] ?? 0) < $now - 86400) unset($a[$k]);
        foreach (['ip:' . df_ip(), 'u:' . strtolower($user)] as $k) {
            if ($ok) { unset($a[$k]); continue; }
            $e = $a[$k] ?? ['n' => 0, 'first' => $now, 'lock' => 0];
            if ($e['first'] < $now - DF_LOGIN_LOCK_MINUTES * 60) $e = ['n' => 0, 'first' => $now, 'lock' => 0];
            $e['n']++;
            if ($e['n'] >= DF_LOGIN_MAX_FAILS) { $e['lock'] = $now + DF_LOGIN_LOCK_MINUTES * 60; $e['n'] = 0; $e['first'] = $now; }
            $a[$k] = $e;
        }
    });
}
function df_login(string $user, string $pass): ?string {
    $wait = df_login_locked($user);
    if ($wait > 0) return 'به دلیل تلاش‌های ناموفق زیاد، ورود تا ' . df_fa_num((string)ceil($wait / 60)) . ' دقیقه‌ی دیگر بسته است.';
    $u = df_users()[$user] ?? null;
    $ok = $u && password_verify($pass, $u['hash']);
    if (!$u) password_verify($pass, '$2y$10$U4oArMFRqpK9hPCN2bQpTer5gxJcHy5.xVjsJ0xAv0/fyHvLgOQRS'); /* constant time-ish */
    df_login_attempt($user, (bool)$ok);
    if (!$ok) return 'نام کاربری یا رمز عبور اشتباه است.';
    /* unlock the data key */
    $newCode = null;
    if (!empty($u['wk'])) {
        $dek = df_unwrap($u, $pass);
        if ($dek === null) return 'کلید رمزنگاری اطلاعات با این رمز باز نشد. از مدیر بخواهید رمز تازه‌ای برایتان تعیین کند، یا با «کد بازیابی» رمز را عوض کنید.';
    } elseif (!df_has_dek()) {
        /* first login ever (or an install from before encryption): create the key and encrypt existing data */
        $dek = random_bytes(32);
        df_update('keys.json', function (array &$k) use ($dek) { $k['kcv'] = df_kcv($dek); $k['created'] = time(); });
        df_log_keys_ensure($dek);
        $newCode = df_rc_set($dek);
        df_update('users.json', function (array &$d) use ($user, $dek, $pass) { $d['users'][$user] = array_merge($d['users'][$user], df_wrap($dek, $pass)); }, ['users' => []]);
        df_migrate_plain($dek);
    } else {
        return 'حساب شما هنوز به کلید رمزنگاری اطلاعات وصل نشده است. از مدیر بخواهید در «تنظیمات عمومی ← کاربران» برایتان رمز تعیین کند.';
    }
    session_regenerate_id(true);
    $_SESSION['u'] = $user; $_SESSION['ver'] = df_users()[$user]['ver'] ?? 1;
    $_SESSION['since'] = $_SESSION['t'] = time();
    $_SESSION['admin'] = !empty($u['admin']);
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
    df_sess_put('dek', $dek);
    if ($newCode) df_sess_put('rc', $newCode);
    return null;
}
/* reset a password with the recovery code */
function df_recover(string $user, string $code, string $pass): ?string {
    $wait = df_login_locked($user);
    if ($wait > 0) return 'به دلیل تلاش‌های ناموفق زیاد، تا ' . df_fa_num((string)ceil($wait / 60)) . ' دقیقه‌ی دیگر امکان این کار نیست.';
    if ($e = df_password_problem($pass)) return $e;
    $k = df_keys();
    $dek = (!empty($k['rk']) && isset(df_users()[$user])) ? df_unwrap($k['rk'], df_rc_norm($code)) : null;
    df_login_attempt($user, $dek !== null);
    if ($dek === null) return 'نام کاربری یا کد بازیابی اشتباه است.';
    $e = df_user_setpass($user, $pass, $dek);
    return $e ?: df_login($user, $pass);
}
function df_logout(): void {
    $_SESSION = [];
    if (session_status() === PHP_SESSION_ACTIVE) { session_regenerate_id(true); }
    if (isset($_COOKIE['DFK']) && !headers_sent()) setcookie('DFK', '', ['expires' => time() - 3600, 'path' => df_base_path(), 'secure' => df_is_https(), 'httponly' => true, 'samesite' => 'Lax']);
}
function df_fa_num(string $s): string { return strtr($s, ['0'=>'۰','1'=>'۱','2'=>'۲','3'=>'۳','4'=>'۴','5'=>'۵','6'=>'۶','7'=>'۷','8'=>'۸','9'=>'۹']); }

/* ---------------- outbound HTTP (fixed, validated URLs only) ---------------- */
function df_http_get(string $url, int $timeout = 8): ?string {
    if (function_exists('curl_init')) {
        $c = curl_init($url);
        curl_setopt_array($c, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 3,
            CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => 5, CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36',
            CURLOPT_HTTPHEADER => ['Accept: text/html,application/json;q=0.9,*/*;q=0.8', 'Accept-Language: fa-IR,fa;q=0.9']]);
        if (defined('CURLOPT_PROTOCOLS')) curl_setopt($c, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
        $r = curl_exec($c);
        $code = (int)curl_getinfo($c, CURLINFO_HTTP_CODE);
        curl_close($c);
        return ($r !== false && $code >= 200 && $code < 300) ? (string)$r : null;
    }
    $ctx = stream_context_create(['http' => ['timeout' => $timeout, 'header' => "User-Agent: Mozilla/5.0\r\n"]]);
    $r = @file_get_contents($url, false, $ctx);
    return $r === false ? null : $r;
}

/* ---------------- document files ---------------- */
function df_safe_segment(string $s): bool {
    return $s !== '' && $s !== '.' && $s !== '..' && mb_strlen($s) <= 140
        && !preg_match('~[/\\\\:*?"<>|\x00-\x1f]~u', $s) && $s[0] !== '.';
}
function df_doc_path(array $parts, string $name): string {
    if (count($parts) < 2 || count($parts) > 3 || $parts[0] !== DF_DOCS_DIR) throw new InvalidArgumentException('bad path');
    foreach ($parts as $p) if (!is_string($p) || !df_safe_segment($p)) throw new InvalidArgumentException('bad path');
    if (count($parts) === 3 && $parts[2] !== DF_TRASH_DIR) throw new InvalidArgumentException('bad path');
    if (!df_safe_segment($name) || !preg_match('~\.html$~u', $name)) throw new InvalidArgumentException('bad name');
    return df_path('files/' . implode('/', $parts) . '/' . $name);
}

/* ---------------- share links ---------------- */
function df_share_public(string $h, array $s, string $dek): array {
    $now = time();
    $state = 'active';
    if (!empty($s['dead'])) $state = $s['dead'];
    elseif (($s['exp'] ?? 0) > 0 && $now > $s['exp']) $state = 'expired';
    elseif (($s['max'] ?? 0) > 0 && ($s['used'] ?? 0) >= $s['max']) $state = 'exhausted';
    $t = !empty($s['te']) ? df_dec((string)base64_decode($s['te']), $dek, 'tok') : null;
    return ['id' => $h, 'url' => $t ? df_base_url() . 'd.php?t=' . $t : '', 'doc' => $s['doc'] ?? '',
        'created' => ($s['created'] ?? 0) * 1000, 'exp' => ($s['exp'] ?? 0) * 1000, 'max' => $s['max'] ?? 0, 'used' => $s['used'] ?? 0,
        'fails' => $s['fails'] ?? 0, 'by' => $s['by'] ?? '', 'state' => $state, 'deadAt' => ($s['deadAt'] ?? 0) * 1000,
        'events' => is_file(df_share_log_file($h)) ? count(file(df_share_log_file($h), FILE_SKIP_EMPTY_LINES | FILE_IGNORE_NEW_LINES) ?: []) : 0];
}

/* ---------------- share access log ----------------
   هر بار که لینک باز می‌شود، رمز وارد می‌شود، فاکتور دیده یا دانلود می‌شود، یک سطر ثبت می‌شود.
   سطرها با کلید عمومیِ گزارش رمز می‌شوند؛ کلید خصوصی‌اش فقط با کلید داده (یعنی بعد از ورود به پنل) باز می‌شود. */
function df_share_log_file(string $h): string { return df_path('share-logs/' . $h . '.log'); }
function df_log_keys_ensure(string $dek): void {
    if (!function_exists('sodium_crypto_box_keypair') || !empty(df_keys()['lpk'])) return;
    $kp = sodium_crypto_box_keypair();
    $pk = sodium_crypto_box_publickey($kp); $sk = sodium_crypto_box_secretkey($kp);
    df_update('keys.json', function (array &$k) use ($pk, $sk, $dek) { if (empty($k['lpk'])) { $k['lpk'] = base64_encode($pk); $k['lsk'] = base64_encode(df_enc($sk, $dek, 'logkey')); } });
}
function df_client_info(): array {
    $h = fn($k) => mb_substr(trim((string)($_SERVER[$k] ?? '')), 0, 400);
    $i = ['ip' => df_ip(), 'ua' => $h('HTTP_USER_AGENT'), 'lang' => $h('HTTP_ACCEPT_LANGUAGE'), 'ref' => $h('HTTP_REFERER')];
    foreach (['HTTP_X_FORWARDED_FOR' => 'xff', 'HTTP_CF_CONNECTING_IP' => 'cfip', 'HTTP_X_REAL_IP' => 'xrip', 'HTTP_CF_IPCOUNTRY' => 'country',
              'HTTP_SEC_CH_UA' => 'chUa', 'HTTP_SEC_CH_UA_FULL_VERSION_LIST' => 'chFull', 'HTTP_SEC_CH_UA_PLATFORM' => 'chPlatform',
              'HTTP_SEC_CH_UA_PLATFORM_VERSION' => 'chPlatformVer', 'HTTP_SEC_CH_UA_MODEL' => 'chModel', 'HTTP_SEC_CH_UA_MOBILE' => 'chMobile',
              'HTTP_SEC_CH_UA_ARCH' => 'chArch', 'HTTP_SEC_CH_UA_BITNESS' => 'chBits', 'HTTP_DEVICE_MEMORY' => 'chMem', 'HTTP_SEC_CH_DEVICE_MEMORY' => 'chMem'] as $k => $n) {
        $v = $h($k); if ($v !== '') $i[$n] = trim($v, '"');
    }
    $i['port'] = (string)($_SERVER['REMOTE_PORT'] ?? '');
    return $i;
}
function df_share_log(string $h, string $event, array $extra = []): void {
    try {
        $rec = ['t' => time(), 'e' => $event] + df_client_info();
        foreach ($extra as $k => $v) $rec[$k] = is_string($v) ? mb_substr($v, 0, 300) : $v;
        $json = json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $pk = df_keys()['lpk'] ?? '';
        $line = $pk && function_exists('sodium_crypto_box_seal') ? 'S:' . base64_encode(sodium_crypto_box_seal($json, base64_decode($pk))) : 'P:' . base64_encode($json);
        $f = df_share_log_file($h);
        if (!is_dir(dirname($f))) @mkdir(dirname($f), 0700, true);
        @file_put_contents($f, $line . "\n", FILE_APPEND | LOCK_EX);
        @chmod($f, 0600);
    } catch (Throwable $e) { error_log('daftar-factor share log: ' . $e->getMessage()); }
}
function df_share_log_read(string $h, string $dek): array {
    $f = df_share_log_file($h);
    if (!is_file($f)) return [];
    $k = df_keys(); $sk = null;
    if (!empty($k['lsk']) && !empty($k['lpk']) && function_exists('sodium_crypto_box_seal_open')) {
        $s = df_dec((string)base64_decode($k['lsk']), $dek, 'logkey');
        if ($s) $sk = sodium_crypto_box_keypair_from_secretkey_and_publickey($s, base64_decode($k['lpk']));
    }
    $out = [];
    foreach (file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
        $j = null;
        if (strncmp($line, 'S:', 2) === 0 && $sk) $j = sodium_crypto_box_seal_open((string)base64_decode(substr($line, 2)), $sk);
        elseif (strncmp($line, 'P:', 2) === 0) $j = base64_decode(substr($line, 2));
        $r = $j ? json_decode($j, true) : null;
        if (is_array($r)) $out[] = $r;
    }
    return $out;
}

/* ---------------- USD rate ---------------- */
function df_rate_per_day(array $r): int { return max(0, min(24, (int)($r['perDay'] ?? DF_RATE_MAX_FETCH_PER_DAY))); }
/* fetch from the internet if allowed today; $force ignores the spacing (manual button) but not the daily cap */
function df_rate_maybe_fetch(bool $force): array {
    $day = date('Y-m-d');
    $go = df_update('rate.json', function (array &$r) use ($day, $force) {
        if (($r['day'] ?? '') !== $day) { $r['day'] = $day; $r['n'] = 0; }
        $per = df_rate_per_day($r);
        if ($per === 0) return 'off';
        if (($r['n'] ?? 0) >= $per) return 'cap';
        if (!$force && time() - (int)(($r['at'] ?? 0) / 1000) < intdiv(86400, $per)) return 'fresh';
        if (!$force && ($r['tryAt'] ?? 0) > time() - 900) return 'fresh'; /* failed recently */
        $r['n'] = ($r['n'] ?? 0) + 1; $r['tryAt'] = time();
        return 'go';
    }, []);
    if ($go !== 'go') return ['status' => $go];
    $got = df_rate_fetch();
    if (!$got) return ['status' => 'fail'];
    df_update('rate.json', function (array &$r) use ($got) { $r['rate'] = $got['rate']; $r['src'] = $got['src']; $r['at'] = time() * 1000; $r['manual'] = false; });
    return ['status' => 'ok'];
}
function df_rate_public(): array {
    $r = df_read('rate.json', []);
    return ['rate' => $r['rate'] ?? 0, 'at' => $r['at'] ?? 0, 'src' => $r['src'] ?? '', 'manual' => !empty($r['manual']),
        'perDay' => df_rate_per_day($r), 'usedToday' => ($r['day'] ?? '') === date('Y-m-d') ? (int)($r['n'] ?? 0) : 0];
}
function df_rate_fetch(): ?array {
    if (DF_NAVASAN_KEY !== '') {
        $t = df_http_get('https://api.navasan.tech/latest/?item=usd_sell&api_key=' . rawurlencode(DF_NAVASAN_KEY));
        $j = $t ? json_decode($t, true) : null;
        $v = isset($j['usd_sell']['value']) ? (float)str_replace(',', '', (string)$j['usd_sell']['value']) : 0;
        if ($v > 10000 && $v < 10000000) return ['rate' => (int)round($v * 10), 'src' => 'navasan.tech'];
    }
    foreach (['https://www.tgju.org/profile/price_dollar_rl', 'https://www.tgju.org/currency'] as $u) {
        $h = df_http_get($u, 10);
        if (!$h) continue;
        $cands = [];
        if (preg_match('~data-col="info\.last_trade\.PDrCotVal"[^>]*>\s*([\d,]+)~', $h, $m)) $cands[] = $m[1];
        if (preg_match('~price_dollar_rl[\s\S]{0,3000}?([1-9]\d{0,2}(?:,\d{3}){2,3})~', $h, $m)) $cands[] = $m[1];
        foreach ($cands as $c) {
            $v = (int)str_replace(',', '', $c);
            if ($v >= 100000 && $v <= 200000000) return ['rate' => $v, 'src' => 'tgju.org'];
        }
    }
    return null;
}

/* ---------------- small pages ---------------- */
function df_page(string $title, string $body, string $nonce = ''): void {
    echo '<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>' . df_h($title) . '</title>'
        . '<style>:root{color-scheme:light dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#eef0ee;color:#1d2321;font:15px/1.8 Vazirmatn,Tahoma,sans-serif;padding:16px}'
        . '@media (prefers-color-scheme:dark){body{background:#121615;color:#e4e8e6}.box{background:#1a1f1e!important;border-color:#2e3533!important}input{background:#202625!important;color:#e4e8e6!important;border-color:#2e3533!important}}'
        . '.box{background:#fff;border:1px solid #d7dbd7;border-radius:14px;padding:22px;width:min(380px,100%);display:flex;flex-direction:column;gap:12px}h1{font-size:19px;margin:0}label{display:flex;flex-direction:column;gap:4px;font-size:13px}'
        . 'input{font:inherit;padding:8px 10px;border:1px solid #c9cfcb;border-radius:8px;background:#f6f7f5;width:100%}input.pin{direction:ltr;text-align:center;font-size:22px;letter-spacing:.4em}'
        . 'button{font:inherit;font-weight:700;padding:9px;border:0;border-radius:8px;background:#1e5a55;color:#fff;cursor:pointer}.err{color:#a8261b;background:#fbe9e7;border-radius:8px;padding:6px 10px;font-size:13.5px}.ok{color:#2c7149}.muted{color:#6b736f;font-size:12.5px}</style>'
        . '</head><body><div class="box">' . $body . '</div></body></html>';
}
function df_json(array $d, int $code = 200): void {
    http_response_code($code);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($d, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}
