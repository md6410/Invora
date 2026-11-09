<?php
/* دفتر فاکتور — رمزنگاری اطلاعات روی سرور
   همه‌ی اطلاعات (سندها، اقلام، مشتریان، کالاها، فایل سندها، پشتیبان‌ها و لینک‌های اشتراک) با یک کلید داده (DEK)
   به روش AES-256-GCM رمز می‌شوند. این کلید هیچ‌جا به‌صورت باز ذخیره نمی‌شود:
   - برای هر کاربر، با کلیدی که از رمز عبور خودش ساخته می‌شود (PBKDF2) قفل شده است؛
   - یک نسخه هم با «کد بازیابی» قفل شده که فقط یک بار به مدیر نشان داده می‌شود؛
   - در طول ورود، کلید در نشست (session) با کلیدی رمز می‌شود که فقط در کوکی مرورگر کاربر است.
   پس داشتن فایل‌های روی هاست به‌تنهایی برای خواندن اطلاعات کافی نیست. */
declare(strict_types=1);
if (!defined('DF')) { http_response_code(403); exit; }

const DF_KDF_ITER = 400000;      /* تکرار PBKDF2 برای رمز عبور کاربران */
const DF_KDF_ITER_RC = 150000;   /* برای کد بازیابی (خودش ۱۲۵ بیت تصادفی است) */
const DF_RC_ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function df_crypto_ok(): bool {
    return function_exists('openssl_encrypt') && in_array('aes-256-gcm', array_map('strtolower', openssl_get_cipher_methods()), true);
}
function df_b64u(string $b): string { return rtrim(strtr(base64_encode($b), '+/', '-_'), '='); }
function df_b64u_dec(string $s): string { return (string)base64_decode(strtr($s, '-_', '+/')); }

/* AES-256-GCM; plaintext is deflated first when zlib is available */
function df_enc(string $plain, string $key, string $aad): string {
    $body = function_exists('gzdeflate') ? "\x01" . gzdeflate($plain, 6) : "\x00" . $plain;
    $iv = random_bytes(12); $tag = '';
    $ct = openssl_encrypt($body, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
    if ($ct === false) throw new RuntimeException('encrypt failed');
    return 'DFE1' . $iv . $tag . $ct;
}
function df_dec(string $blob, string $key, string $aad): ?string {
    if (strlen($blob) < 33 || strncmp($blob, 'DFE1', 4) !== 0) return null;
    $p = openssl_decrypt(substr($blob, 32), 'aes-256-gcm', $key, OPENSSL_RAW_DATA, substr($blob, 4, 12), substr($blob, 16, 16), $aad);
    if ($p === false || $p === '') return null;
    if ($p[0] === "\x01") { $r = @gzinflate(substr($p, 1)); return $r === false ? null : $r; }
    return substr($p, 1);
}
function df_is_enc(string $blob): bool { return strncmp($blob, 'DFE1', 4) === 0; }

/* ---------- key wrapping ---------- */
function df_kdf(string $secret, array $p): string {
    return hash_pbkdf2('sha256', $secret, base64_decode($p['s']), (int)$p['i'], 32, true);
}
function df_wrap(string $dek, string $secret, int $iter = DF_KDF_ITER): array {
    $p = ['a' => 'pbkdf2-sha256', 's' => base64_encode(random_bytes(16)), 'i' => $iter];
    return ['kdf' => $p, 'wk' => base64_encode(df_enc($dek, df_kdf($secret, $p), 'wrap'))];
}
function df_unwrap(array $w, string $secret): ?string {
    if (empty($w['wk']) || empty($w['kdf']['s'])) return null;
    $dek = df_dec((string)base64_decode($w['wk']), df_kdf($secret, $w['kdf']), 'wrap');
    return ($dek !== null && df_kcv_ok($dek)) ? $dek : null;
}
function df_keys(): array { return df_read('keys.json', []); }
function df_kcv(string $dek): string { return hash_hmac('sha256', 'df-kcv', $dek); }
function df_kcv_ok(string $dek): bool { $k = df_keys(); return !empty($k['kcv']) && hash_equals($k['kcv'], df_kcv($dek)); }
function df_has_dek(): bool { return !empty(df_keys()['kcv']); }

/* ---------- recovery code ---------- */
function df_rc_new(): string {
    $a = DF_RC_ALPHA; $o = '';
    for ($i = 0; $i < 25; $i++) $o .= $a[random_int(0, 31)];
    return implode('-', str_split($o, 5));
}
function df_rc_norm(string $c): string { return preg_replace('/[^' . DF_RC_ALPHA . ']/', '', strtoupper(df_fa_digits($c))); }
function df_rc_set(string $dek): string {
    $code = df_rc_new();
    df_update('keys.json', function (array &$k) use ($dek, $code) { $k['rk'] = df_wrap($dek, df_rc_norm($code), DF_KDF_ITER_RC); $k['rkAt'] = time(); });
    return $code;
}

/* ---------- per-browser session secret (key lives only in the user's cookie) ---------- */
function df_cookie_key(bool $create): ?string {
    $v = $_COOKIE['DFK'] ?? '';
    if (is_string($v) && preg_match('/^[A-Za-z0-9_-]{43}$/', $v)) { $k = df_b64u_dec($v); if (strlen($k) === 32) return $k; }
    if (!$create) return null;
    $k = random_bytes(32);
    setcookie('DFK', df_b64u($k), ['expires' => 0, 'path' => df_base_path(), 'secure' => df_is_https(), 'httponly' => true, 'samesite' => 'Lax']);
    $_COOKIE['DFK'] = df_b64u($k);
    return $k;
}
function df_sess_put(string $name, string $secret): void {
    $_SESSION['sec'][$name] = base64_encode(df_enc($secret, df_cookie_key(true), 'sess:' . $name));
}
function df_sess_get(string $name): ?string {
    $b = $_SESSION['sec'][$name] ?? null;
    if (!is_string($b)) return null;
    $ck = df_cookie_key(false);
    return $ck ? df_dec((string)base64_decode($b), $ck, 'sess:' . $name) : null;
}
function df_sess_del(string $name): void { unset($_SESSION['sec'][$name]); }
function df_dek(): ?string { static $d = null; if ($d === null) $d = df_sess_get('dek') ?? ''; return $d === '' ? null : $d; }

/* ---------- encrypted storage ---------- */
function df_sread(string $rel, string $dek, string $aad): ?string {
    $p = df_path($rel);
    if (!is_file($p)) return null;
    $raw = (string)file_get_contents($p);
    if (!df_is_enc($raw)) return $raw; /* legacy plaintext (migrated on the next login) */
    $r = df_dec($raw, $dek, $aad);
    if ($r === null) throw new RuntimeException('decrypt failed: ' . $rel);
    return $r;
}
function df_swrite(string $rel, string $plain, string $dek, string $aad): void {
    df_write_atomic(df_path($rel), df_enc($plain, $dek, $aad));
}
/* document files: names on disk are keyed hashes, so buyer names and dates are not visible either */
function df_doc_store(array $parts, string $name, string $dek): string {
    df_doc_path($parts, $name); /* validates */
    $nk = hash_hmac('sha256', 'df-names', $dek, true);
    $d = substr(hash_hmac('sha256', 'd:' . $parts[1], $nk), 0, 24);
    $f = substr(hash_hmac('sha256', 'f:' . implode('/', $parts) . '/' . $name, $nk), 0, 32);
    return 'files/' . $d . '/' . $f . '.bin';
}

/* accounting attachments: file names on disk are keyed hashes too */
function df_att_path(string $id, string $dek): string {
    return 'attach/' . substr(hash_hmac('sha256', 'att:' . $id, hash_hmac('sha256', 'df-names', $dek, true)), 0, 40) . '.bin';
}

/* ---------- share links ---------- */
function df_share_hash(string $t): string { return hash('sha256', 'df-share:' . $t); }
function df_share_title_key(string $t): string { return hash_hmac('sha256', 'df-share-title', $t, true); }
function df_share_file_key(string $t, string $pin, int $pk): string {
    return $pk ? hash_pbkdf2('sha256', $t . '|' . $pin, 'df-share-file', 20000, 32, true) : hash_hmac('sha256', 'df-share-file', $t, true);
}
function df_share_file(string $h): string { return df_path('shares/' . $h . '.bin'); }

/* ---------- one-time migration of data written before encryption existed ---------- */
function df_migrate_plain(string $dek): void {
    foreach (array_merge([df_path('state.json')], glob(df_path('backups/state-*.json')) ?: []) as $f) {
        $raw = (string)@file_get_contents($f);
        if ($raw !== '' && !df_is_enc($raw)) df_write_atomic($f, df_enc($raw, $dek, 'state'));
    }
    $legacy = df_path('files/' . DF_DOCS_DIR);
    if (is_dir($legacy)) {
        foreach (glob($legacy . '/*', GLOB_ONLYDIR) ?: [] as $cdir) {
            $sets = [[basename($cdir), $cdir, false]];
            if (is_dir($cdir . '/' . DF_TRASH_DIR)) $sets[] = [basename($cdir), $cdir . '/' . DF_TRASH_DIR, true];
            foreach ($sets as [$co, $dir, $trash]) {
                foreach (glob($dir . '/*.html') ?: [] as $f) {
                    $parts = [DF_DOCS_DIR, $co]; if ($trash) $parts[] = DF_TRASH_DIR;
                    try {
                        $rel = df_doc_store($parts, basename($f), $dek);
                        df_swrite($rel, json_encode(['parts' => $parts, 'name' => basename($f), 'content' => (string)file_get_contents($f)], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), $dek, 'file');
                        @unlink($f);
                    } catch (Throwable $e) { error_log('daftar-factor migrate: ' . $e->getMessage()); }
                }
                @rmdir($dir);
            }
            @rmdir($cdir);
        }
        @rmdir($legacy);
    }
    $sh = df_read('shares.json', []);
    if ($sh && array_filter(array_keys($sh), fn($k) => preg_match('/^[a-f0-9]{32}$/', (string)$k))) {
        df_update('shares.json', function (array &$all) use ($dek) {
            foreach (array_keys($all) as $t) {
                if (!preg_match('/^[a-f0-9]{32}$/', (string)$t)) continue;
                $r = $all[$t]; $h = df_share_hash($t);
                $old = df_path('shares/' . $t . '.html');
                if (is_file($old)) { df_write_atomic(df_share_file($h), df_enc((string)file_get_contents($old), df_share_file_key($t, '', 0), 'share')); @unlink($old); }
                $r['te'] = base64_encode(df_enc($t, $dek, 'tok'));
                $r['tt'] = base64_encode(df_enc((string)($r['title'] ?? ''), df_share_title_key($t), 'title'));
                $r['pk'] = 0; $r['dead'] = $r['dead'] ?? '';
                unset($r['title']);
                unset($all[$t]); $all[$h] = $r;
            }
        });
    }
}
