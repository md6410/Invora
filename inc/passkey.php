<?php
/* دفتر فاکتور — ورود با اثر انگشت / چهره / پین دستگاه (WebAuthn، Passkey) و «دستگاه‌های مورد اعتماد»

   ------------------------------------------------------------
   چرا «دستگاه مورد اعتماد» لازم است
   همه‌ی اطلاعات با کلید داده (DEK) رمز شده و این کلید فقط با رمز عبور کاربر باز می‌شود. اثر انگشت و کد پیامکی
   رمز عبور نیستند؛ پس به‌تنهایی نمی‌توانند کلید را باز کنند. راه‌حل:
     - وقتی کاربر (بعد از ورود با رمز) روی یک دستگاه «ورود با اثر انگشت» یا «ورود با پیامک» را فعال می‌کند،
       یک راز تصادفی ۳۲ بایتی در کوکیِ همان مرورگر (DFDEV، httpOnly، ماندگار) گذاشته می‌شود؛
     - کلید داده با کلیدی که از همین راز ساخته می‌شود قفل و در users.json کنار نام کاربر نگه داشته می‌شود.
   پس برای باز شدن اطلاعات هر دو لازم است: کوکیِ همان دستگاه + اثبات هویت (امضای اثر انگشت یا کد پیامک).
   فایل‌های روی هاست به‌تنهایی کافی نیستند و دزدیدن کوکی به‌تنهایی هم کافی نیست.

   ------------------------------------------------------------
   WebAuthn: هسته‌ی سنجش (CBOR، تبدیل کلید COSE به PEM، authenticatorData، challenge، امضا) از پروژه‌ی وبی
   گرفته شده و بدون کتابخانه‌ی بیرونی است. attestation عمداً «none» است (برای بانک لازم است، نه برای اینجا)؛
   دامنه، challenge، پرچم «کاربر تأیید شد» و خود امضا سنجیده می‌شوند. */
declare(strict_types=1);
if (!defined('DF')) { http_response_code(403); exit; }

const DF_PK_TTL = 180;                 /* اعتبار هر challenge (ثانیه) */
const DF_DEV_COOKIE = 'DFDEV';

/* ---------- base64url ---------- */
function pk_b64u_decode(string $s): string {
    $s = strtr(trim($s), '-_', '+/');
    $pad = strlen($s) % 4;
    if ($pad === 1) return '';
    if ($pad) $s .= str_repeat('=', 4 - $pad);
    $o = base64_decode($s, true);
    return $o === false ? '' : $o;
}

/* ---------- دامنه ---------- */
function pk_rp_id(): string {
    $h = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
    $h = preg_replace('/:\d+$/', '', $h);
    return preg_match('/^[a-z0-9.\-]+$/', (string)$h) ? (string)$h : '';
}
function pk_origin(): string {
    $host = strtolower((string)($_SERVER['HTTP_HOST'] ?? ''));
    return (df_is_https() ? 'https' : 'http') . '://' . $host;
}

/* ---------- CBOR (فقط آنچه WebAuthn لازم دارد) ---------- */
function pk_cbor_uint(string $s, int &$i, int $bytes): int {
    if ($i + $bytes > strlen($s)) throw new RuntimeException('cbor: end');
    $v = 0;
    for ($k = 0; $k < $bytes; $k++) $v = ($v << 8) | ord($s[$i + $k]);
    $i += $bytes;
    return $v;
}
function pk_cbor_value(string $s, int &$i) {
    $n = strlen($s);
    if ($i >= $n) throw new RuntimeException('cbor: end');
    $ib = ord($s[$i++]); $major = $ib >> 5; $ai = $ib & 0x1f; $len = $ai;
    if ($ai === 24) $len = pk_cbor_uint($s, $i, 1);
    elseif ($ai === 25) $len = pk_cbor_uint($s, $i, 2);
    elseif ($ai === 26) $len = pk_cbor_uint($s, $i, 4);
    elseif ($ai === 27) $len = pk_cbor_uint($s, $i, 8);
    elseif ($ai >= 28) throw new RuntimeException('cbor: unsupported');
    switch ($major) {
        case 0: return $len;
        case 1: return -1 - $len;
        case 2: case 3:
            if ($len < 0 || $i + $len > $n) throw new RuntimeException('cbor: length');
            $o = substr($s, $i, $len); $i += $len; return $o;
        case 4: $a = []; for ($k = 0; $k < $len; $k++) $a[] = pk_cbor_value($s, $i); return $a;
        case 5:
            $m = [];
            for ($k = 0; $k < $len; $k++) {
                $key = pk_cbor_value($s, $i);
                if (!is_int($key) && !is_string($key)) throw new RuntimeException('cbor: key');
                $m[$key] = pk_cbor_value($s, $i);
            }
            return $m;
        case 6: return pk_cbor_value($s, $i);
        case 7:
            if ($ai === 20) return false; if ($ai === 21) return true; if ($ai === 22) return null;
            throw new RuntimeException('cbor: simple');
    }
    throw new RuntimeException('cbor: type');
}
function pk_cbor_decode(string $s): ?array {
    try { $i = 0; $v = pk_cbor_value($s, $i); return is_array($v) ? $v : null; } catch (Throwable $e) { return null; }
}

/* ---------- کلید COSE → PEM (ES256 و RS256) ---------- */
function pk_der_len(int $n): string {
    if ($n < 0x80) return chr($n);
    $b = ''; while ($n > 0) { $b = chr($n & 0xff) . $b; $n >>= 8; }
    return chr(0x80 | strlen($b)) . $b;
}
function pk_der(int $tag, string $body): string { return chr($tag) . pk_der_len(strlen($body)) . $body; }
function pk_der_uint(string $bin): string {
    $bin = ltrim($bin, "\x00"); if ($bin === '') $bin = "\x00";
    if (ord($bin[0]) & 0x80) $bin = "\x00" . $bin;
    return pk_der(0x02, $bin);
}
function pk_pem(string $der): string { return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n"; }
function pk_cose_to_pem(array $c): ?string {
    $kty = $c[1] ?? null; $alg = (int)($c[3] ?? 0);
    if ($kty === 2 && $alg === -7) {
        $x = (string)($c[-2] ?? ''); $y = (string)($c[-3] ?? '');
        if ((int)($c[-1] ?? 0) !== 1 || strlen($x) !== 32 || strlen($y) !== 32) return null;
        $algId = pk_der(0x30, pk_der(0x06, "\x2a\x86\x48\xce\x3d\x02\x01") . pk_der(0x06, "\x2a\x86\x48\xce\x3d\x03\x01\x07"));
        return pk_pem(pk_der(0x30, $algId . pk_der(0x03, "\x00\x04" . $x . $y)));
    }
    if ($kty === 3 && $alg === -257) {
        $n = (string)($c[-1] ?? ''); $e = (string)($c[-2] ?? '');
        if ($n === '' || $e === '') return null;
        $algId = pk_der(0x30, pk_der(0x06, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01") . pk_der(0x05, ''));
        return pk_pem(pk_der(0x30, $algId . pk_der(0x03, "\x00" . pk_der(0x30, pk_der_uint($n) . pk_der_uint($e)))));
    }
    return null;
}

/* ---------- authenticatorData ---------- */
function pk_auth_data(string $d): ?array {
    if (strlen($d) < 37) return null;
    $o = ['rp' => substr($d, 0, 32), 'flags' => ord($d[32]), 'count' => unpack('N', substr($d, 33, 4))[1], 'cred' => '', 'cose' => null];
    $o['uv'] = (bool)($o['flags'] & 0x04); $o['at'] = (bool)($o['flags'] & 0x40);
    if (!$o['at']) return $o;
    if (strlen($d) < 55) return null;
    $len = unpack('n', substr($d, 53, 2))[1];
    if ($len <= 0 || strlen($d) < 55 + $len) return null;
    $o['cred'] = substr($d, 55, $len);
    $i = 0;
    try { $cose = pk_cbor_value(substr($d, 55 + $len), $i); } catch (Throwable $e) { return null; }
    if (!is_array($cose)) return null;
    $o['cose'] = $cose;
    return $o;
}

/* ---------- challenge: یک‌بارمصرف، در نشست ---------- */
function pk_challenge(string $for): string {
    $c = df_b64u(random_bytes(32));
    $_SESSION['pkch'] = ['v' => $c, 'for' => $for, 'exp' => time() + DF_PK_TTL];
    return $c;
}
function pk_client_ok(string $json, string $type, string $for): ?string {
    $c = json_decode($json, true);
    $ch = $_SESSION['pkch'] ?? null; unset($_SESSION['pkch']);
    if (!is_array($c)) return 'پاسخ مرورگر خوانده نشد.';
    if (($c['type'] ?? '') !== $type) return 'نوع درخواست با پاسخ نمی‌خواند.';
    if (!is_array($ch) || ($ch['for'] ?? '') !== $for || (int)($ch['exp'] ?? 0) < time() || !hash_equals((string)$ch['v'], (string)($c['challenge'] ?? '')))
        return 'مهلت این درخواست تمام شده؛ دوباره امتحان کنید.';
    if (($c['origin'] ?? '') !== pk_origin()) return 'این درخواست از نشانی دیگری آمده است.';
    return null;
}

/* ---------- ثبت کلید (کاربرِ واردشده) ---------- */
function pk_label(string $ua): string {
    foreach (['iPhone' => 'آیفون', 'iPad' => 'آیپد', 'Android' => 'اندروید', 'Windows' => 'ویندوز', 'Mac OS' => 'مک', 'Linux' => 'لینوکس'] as $k => $v)
        if (stripos($ua, $k) !== false) return $v . (stripos($ua, 'Edg/') !== false ? ' · Edge' : (stripos($ua, 'Chrome') !== false ? ' · Chrome' : (stripos($ua, 'Firefox') !== false ? ' · Firefox' : (stripos($ua, 'Safari') !== false ? ' · Safari' : ''))));
    return 'دستگاه';
}
function pk_reg_options(string $user, bool $compat): array {
    $exclude = [];
    foreach ((df_users()[$user]['pks'] ?? []) as $id => $k) $exclude[] = ['type' => 'public-key', 'id' => $id];
    $o = ['challenge' => pk_challenge('reg'), 'rp' => ['id' => pk_rp_id(), 'name' => 'Invora'],
        'user' => ['id' => df_b64u(hash('sha256', 'df-pk-user:' . $user, true)), 'name' => $user, 'displayName' => $user . ' — Invora'],
        'pubKeyCredParams' => [['type' => 'public-key', 'alg' => -7], ['type' => 'public-key', 'alg' => -257]],
        'timeout' => 120000, 'attestation' => 'none', 'excludeCredentials' => $exclude,
        'authenticatorSelection' => ['authenticatorAttachment' => 'platform', 'residentKey' => 'preferred', 'requireResidentKey' => false, 'userVerification' => 'required']];
    if ($compat) { /* تلاش دوم (همان ترکیبی که در وبی روی گوشی‌های سامسونگ جواب داد) */
        $o['authenticatorSelection'] = ['authenticatorAttachment' => 'platform', 'residentKey' => 'discouraged', 'requireResidentKey' => false, 'userVerification' => 'preferred'];
        $o['excludeCredentials'] = [];
    }
    return $o;
}
/** @return string|null خطا، یا null یعنی ثبت شد */
function pk_reg_verify(string $user, string $dek, array $r): ?string {
    $cj = pk_b64u_decode((string)($r['clientDataJSON'] ?? '')); $ao = pk_b64u_decode((string)($r['attestationObject'] ?? ''));
    if ($cj === '' || $ao === '') return 'پاسخ مرورگر ناقص بود.';
    if ($e = pk_client_ok($cj, 'webauthn.create', 'reg')) return $e;
    $att = pk_cbor_decode($ao);
    $ad = ($att && is_string($att['authData'] ?? null)) ? pk_auth_data($att['authData']) : null;
    if (!$ad || !$ad['at'] || $ad['cred'] === '' || !is_array($ad['cose'])) return 'داده‌ی دستگاه ناقص است.';
    if (!hash_equals(hash('sha256', pk_rp_id(), true), $ad['rp'])) return 'این کلید برای سایت دیگری ساخته شده است.';
    if (!$ad['uv']) return 'دستگاه، اثر انگشت/چهره یا پین را تأیید نکرد.';
    $pem = pk_cose_to_pem($ad['cose']);
    if ($pem === null) return 'نوع کلید این دستگاه پشتیبانی نمی‌شود.';
    $id = df_b64u($ad['cred']);
    foreach (df_users() as $n => $u) if ($n !== $user && isset($u['pks'][$id])) return 'این کلید برای کاربر دیگری ثبت شده است.';
    $did = df_dev_ensure($user, $dek, ['pk' => true]);
    $label = pk_label((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
    df_update('users.json', function (array &$d) use ($user, $id, $pem, $ad, $label, $did) {
        if (!isset($d['users'][$user])) return;
        $d['users'][$user]['pks'][$id] = ['pem' => $pem, 'count' => $ad['count'], 'at' => time(), 'last' => 0, 'label' => $label, 'dev' => $did];
    }, ['users' => []]);
    return null;
}

/* ---------- ورود ---------- */
function pk_login_options(): array {
    return ['challenge' => pk_challenge('login'), 'rpId' => pk_rp_id(), 'timeout' => 120000, 'userVerification' => 'required', 'allowCredentials' => df_dev_creds()];
}
/* کلیدهای ثبت‌شده از همین دستگاه (برای وقتی که کلید «قابل کشف» ساخته نشده) */
function df_dev_creds(): array {
    $did = df_dev_id(); if ($did === '') return [];
    $out = [];
    foreach (df_users() as $u) foreach (($u['pks'] ?? []) as $id => $k) if (($k['dev'] ?? '') === $did) $out[] = ['type' => 'public-key', 'id' => $id];
    return $out;
}
/** @return array{0:?string,1:?string} [کاربر، خطا] */
function pk_login_verify(array $r): array {
    $id = (string)($r['id'] ?? '');
    $cj = pk_b64u_decode((string)($r['clientDataJSON'] ?? '')); $ad0 = pk_b64u_decode((string)($r['authenticatorData'] ?? '')); $sig = pk_b64u_decode((string)($r['signature'] ?? ''));
    if ($id === '' || $cj === '' || $ad0 === '' || $sig === '') return [null, 'پاسخ مرورگر ناقص بود.'];
    $user = null; $k = null;
    foreach (df_users() as $n => $u) if (isset($u['pks'][$id])) { $user = (string)$n; $k = $u['pks'][$id]; break; }
    if ($user === null) { unset($_SESSION['pkch']); return [null, 'این اثر انگشت برای هیچ کاربری ثبت نشده است.']; }
    if ($e = pk_client_ok($cj, 'webauthn.get', 'login')) return [null, $e];
    $ad = pk_auth_data($ad0);
    if (!$ad || !hash_equals(hash('sha256', pk_rp_id(), true), $ad['rp'])) return [null, 'این کلید برای سایت دیگری است.'];
    if (!$ad['uv']) return [null, 'دستگاه، اثر انگشت/چهره یا پین را تأیید نکرد.'];
    if (@openssl_verify($ad0 . hash('sha256', $cj, true), $sig, (string)$k['pem'], OPENSSL_ALGO_SHA256) !== 1) return [null, 'امضای دستگاه تأیید نشد.'];
    $was = (int)($k['count'] ?? 0); $now = (int)$ad['count'];
    if ($was > 0 && $now > 0 && $now <= $was) return [null, 'این کلید معتبر نیست (شمارنده عقب رفته). با رمز وارد شوید و دستگاه را دوباره ثبت کنید.'];
    df_update('users.json', function (array &$d) use ($user, $id, $now, $was) {
        if (isset($d['users'][$user]['pks'][$id])) { $d['users'][$user]['pks'][$id]['count'] = max($now, $was); $d['users'][$user]['pks'][$id]['last'] = time(); }
    }, ['users' => []]);
    return [$user, null];
}

/* ============================================================
   دستگاه‌های مورد اعتماد
   ============================================================ */
function df_dev_secret(bool $create): ?string {
    $v = (string)($_COOKIE[DF_DEV_COOKIE] ?? '');
    if (preg_match('/^[A-Za-z0-9_-]{43}$/', $v)) { $k = df_b64u_dec($v); if (strlen($k) === 32) return $k; }
    if (!$create) return null;
    $k = random_bytes(32);
    setcookie(DF_DEV_COOKIE, df_b64u($k), ['expires' => time() + 400 * 86400, 'path' => df_base_path(), 'secure' => df_is_https(), 'httponly' => true, 'samesite' => 'Strict']);
    $_COOKIE[DF_DEV_COOKIE] = df_b64u($k);
    return $k;
}
function df_dev_id(): string { $s = df_dev_secret(false); return $s === null ? '' : substr(hash('sha256', 'df-dev:' . $s), 0, 24); }
/* کلید داده را برای این دستگاه قفل می‌کند (اگر نبود) و ویژگی‌ها را روشن می‌کند؛ شناسه‌ی دستگاه را برمی‌گرداند */
function df_dev_ensure(string $user, string $dek, array $flags): string {
    $s = df_dev_secret(true);
    $did = substr(hash('sha256', 'df-dev:' . $s), 0, 24);
    $wk = base64_encode(df_enc($dek, hash_hmac('sha256', 'df-dev-key', $s, true), 'dev'));
    $label = pk_label((string)($_SERVER['HTTP_USER_AGENT'] ?? ''));
    df_update('users.json', function (array &$d) use ($user, $did, $wk, $label, $flags) {
        if (!isset($d['users'][$user])) return;
        $x = $d['users'][$user]['devs'][$did] ?? ['at' => time(), 'last' => 0, 'label' => $label];
        $x['wk'] = $wk;
        foreach ($flags as $k => $v) $x[$k] = (bool)$v;
        $d['users'][$user]['devs'][$did] = $x;
    }, ['users' => []]);
    return $did;
}
/* کلید داده‌ی این کاربر روی این دستگاه؛ null اگر این دستگاه برای او فعال نشده */
function df_dev_dek(string $user, string $need): ?string {
    $s = df_dev_secret(false); if ($s === null) return null;
    $did = substr(hash('sha256', 'df-dev:' . $s), 0, 24);
    $x = df_users()[$user]['devs'][$did] ?? null;
    if (!is_array($x) || empty($x[$need]) || empty($x['wk'])) return null;
    $dek = df_dec((string)base64_decode((string)$x['wk']), hash_hmac('sha256', 'df-dev-key', $s, true), 'dev');
    if ($dek === null || !df_kcv_ok($dek)) return null;
    df_update('users.json', function (array &$d) use ($user, $did) { if (isset($d['users'][$user]['devs'][$did])) $d['users'][$user]['devs'][$did]['last'] = time(); }, ['users' => []]);
    return $dek;
}
/* فهرست دستگاه‌ها و کلیدهای یک کاربر برای صفحه‌ی «حساب کاربری» */
function df_dev_public(string $user): array {
    $u = df_users()[$user] ?? []; $me = df_dev_id(); $devs = []; $pks = [];
    foreach (($u['devs'] ?? []) as $id => $x) $devs[] = ['id' => $id, 'label' => $x['label'] ?? '', 'at' => ($x['at'] ?? 0) * 1000, 'last' => ($x['last'] ?? 0) * 1000, 'pk' => !empty($x['pk']), 'sms' => !empty($x['sms']), 'me' => $id === $me];
    foreach (($u['pks'] ?? []) as $id => $k) $pks[] = ['id' => $id, 'label' => $k['label'] ?? '', 'at' => ($k['at'] ?? 0) * 1000, 'last' => ($k['last'] ?? 0) * 1000, 'dev' => $k['dev'] ?? '', 'me' => ($k['dev'] ?? '') === $me];
    return ['devs' => $devs, 'pks' => $pks, 'me' => $me, 'mobile' => (string)($u['mobile'] ?? '')];
}
function df_dev_remove(string $user, string $did): void {
    df_update('users.json', function (array &$d) use ($user, $did) {
        if (!isset($d['users'][$user])) return;
        unset($d['users'][$user]['devs'][$did]);
        foreach (($d['users'][$user]['pks'] ?? []) as $id => $k) if (($k['dev'] ?? '') === $did) unset($d['users'][$user]['pks'][$id]);
    }, ['users' => []]);
}
function df_pk_remove(string $user, string $id): void {
    df_update('users.json', function (array &$d) use ($user, $id) {
        if (!isset($d['users'][$user]['pks'][$id])) return;
        $did = (string)($d['users'][$user]['pks'][$id]['dev'] ?? '');
        unset($d['users'][$user]['pks'][$id]);
        $left = array_filter($d['users'][$user]['pks'] ?? [], fn($k) => ($k['dev'] ?? '') === $did);
        if ($did !== '' && !$left && isset($d['users'][$user]['devs'][$did])) {
            $d['users'][$user]['devs'][$did]['pk'] = false;
            if (empty($d['users'][$user]['devs'][$did]['sms'])) unset($d['users'][$user]['devs'][$did]);
        }
    }, ['users' => []]);
}
function df_pk_any(): bool { foreach (df_users() as $u) if (!empty($u['pks'])) return true; return false; }
