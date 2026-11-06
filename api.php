<?php
/* دفتر فاکتور — API برای نسخه‌ی تحت وب (فقط برای کاربر واردشده). همه‌ی اطلاعات رمزشده ذخیره می‌شوند. */
declare(strict_types=1);
define('DF', 1);
require __DIR__ . '/inc/lib.php';

df_headers('api');
df_session_start();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') df_json(['ok' => false, 'error' => 'method'], 405);
if (!df_logged_in()) df_json(['ok' => false, 'error' => 'auth'], 401);
if (!df_csrf_ok((string)($_SERVER['HTTP_X_CSRF_TOKEN'] ?? ''))) df_json(['ok' => false, 'error' => 'csrf'], 403);
$user = (string)$_SESSION['u'];
$admin = !empty($_SESSION['admin']);
$dek = df_dek();
session_write_close(); /* no session writes below (except pass_change); avoids blocking parallel requests */

$in = json_decode((string)file_get_contents('php://input'), true);
if (!is_array($in)) df_json(['ok' => false, 'error' => 'bad request'], 400);
$a = (string)($in['a'] ?? '');
$J = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES;

try {
    switch ($a) {
        case 'state_get': {
            $meta = df_read('state-meta.json', ['rev' => 0]);
            $txt = df_sread('state.json', $dek, 'state');
            df_json(['ok' => true, 'rev' => (int)$meta['rev'], 'state' => $txt === null ? null : json_decode($txt, true)]);
        }
        case 'state_save': {
            $state = $in['state'] ?? null;
            if (!is_array($state) || ($state['app'] ?? '') !== 'daftar-factor') df_json(['ok' => false, 'error' => 'bad state'], 400);
            $rev = (int)($in['rev'] ?? -1);
            $force = !empty($in['force']);
            $blob = df_enc(json_encode($state, $J), $dek, 'state');
            $res = df_update('state-meta.json', function (array &$m) use ($rev, $force, $blob, $user) {
                $cur = (int)($m['rev'] ?? 0);
                if (!$force && $rev !== $cur) return ['conflict' => true, 'rev' => $cur, 'by' => $m['by'] ?? ''];
                df_write_atomic(df_path('state.json'), $blob);
                df_write_atomic(df_path('backups/state-' . date('Y-m-d') . '.json'), $blob);
                $m = ['rev' => $cur + 1, 'by' => $user, 'at' => time()];
                return ['rev' => $cur + 1];
            }, ['rev' => 0]);
            if (!empty($res['conflict'])) df_json(['ok' => false, 'error' => 'conflict', 'rev' => $res['rev'], 'by' => $res['by']], 409);
            if (random_int(1, 20) === 1) { /* keep the last 90 daily backups */
                $b = glob(df_path('backups/state-*.json')) ?: [];
                sort($b);
                foreach (array_slice($b, 0, max(0, count($b) - 90)) as $f) @unlink($f);
            }
            df_json(['ok' => true, 'rev' => $res['rev']]);
        }
        case 'time':
            df_json(['ok' => true, 'ms' => (int)round(microtime(true) * 1000)]);
        case 'hol': {
            $y = (int)($in['y'] ?? 0); $m = (int)($in['m'] ?? 0); $d = (int)($in['d'] ?? 0);
            if ($y < 1300 || $y > 1600 || $m < 1 || $m > 12 || $d < 1 || $d > 31) df_json(['ok' => false, 'error' => 'bad date'], 400);
            $q = sprintf('%d/%02d/%02d', $y, $m, $d);
            foreach (['https://holidayapi.ir/jalali/', 'https://persiancalapi.ir/jalali/'] as $base) {
                $t = df_http_get($base . $q, 8);
                $j = $t ? json_decode($t, true) : null;
                if (is_array($j) && array_key_exists('is_holiday', $j)) df_json(['ok' => true, 'data' => $j, 'src' => parse_url($base, PHP_URL_HOST)]);
            }
            df_json(['ok' => false, 'error' => 'holiday service unreachable'], 502);
        }

        /* ---------- document files (encrypted; names on disk are hashed) ---------- */
        case 'file_put': {
            $parts = (array)($in['parts'] ?? []); $name = (string)($in['name'] ?? '');
            $c = (string)($in['content'] ?? '');
            if (strlen($c) > 8 * 1024 * 1024) df_json(['ok' => false, 'error' => 'too large'], 413);
            df_swrite(df_doc_store($parts, $name, $dek), json_encode(['parts' => $parts, 'name' => $name, 'content' => $c], $J), $dek, 'file');
            df_json(['ok' => true]);
        }
        case 'file_del': {
            $p = df_path(df_doc_store((array)($in['parts'] ?? []), (string)($in['name'] ?? ''), $dek));
            if (is_file($p)) @unlink($p);
            @rmdir(dirname($p));
            df_json(['ok' => true]);
        }
        case 'file_scan': {
            $out = [];
            foreach (glob(df_path('files/*/*.bin')) ?: [] as $f) {
                if (count($out) >= 3000) break;
                $j = df_dec((string)file_get_contents($f), $dek, 'file');
                $r = $j ? json_decode($j, true) : null;
                if (is_array($r) && isset($r['content'])) $out[] = ['parts' => $r['parts'] ?? [], 'name' => $r['name'] ?? '', 'content' => $r['content']];
            }
            df_json(['ok' => true, 'files' => $out]);
        }

        /* ---------- share links ---------- */
        case 'share_create': {
            $doc = (string)($in['docId'] ?? '');
            $html = (string)($in['html'] ?? '');
            if ($doc === '' || strlen($doc) > 64 || $html === '' || strlen($html) > 8 * 1024 * 1024) df_json(['ok' => false, 'error' => 'bad input'], 400);
            $exp = (int)floor(((int)($in['exp'] ?? 0)) / 1000);
            if ($exp !== 0 && ($exp < time() + 60 || $exp > time() + 366 * 86400)) df_json(['ok' => false, 'error' => 'زمان انقضا معتبر نیست.'], 400);
            $max = max(0, min(10000, (int)($in['max'] ?? 0)));
            $pin = df_fa_digits(trim((string)($in['pin'] ?? '')));
            if ($pin === '') $pin = str_pad((string)random_int(0, 99999), 5, '0', STR_PAD_LEFT);
            elseif (!preg_match('/^\d{4,5}$/', $pin)) df_json(['ok' => false, 'error' => 'رمز باید ۴ یا ۵ رقم باشد.'], 400);
            df_log_keys_ensure($dek);
            $t = bin2hex(random_bytes(16)); $h = df_share_hash($t);
            df_write_atomic(df_share_file($h), df_enc($html, df_share_file_key($t, $pin, 1), 'share'));
            $title = mb_substr((string)($in['title'] ?? ''), 0, 160);
            $rec = ['doc' => $doc, 'created' => time(), 'by' => $user, 'exp' => $exp, 'max' => $max, 'used' => 0, 'fails' => 0, 'last' => 0,
                'pin' => password_hash($pin, PASSWORD_DEFAULT), 'pk' => 1, 'dead' => '',
                'te' => base64_encode(df_enc($t, $dek, 'tok')), 'tt' => base64_encode(df_enc($title, df_share_title_key($t), 'title'))];
            df_update('shares.json', function (array &$all) use ($h, $rec) { $all[$h] = $rec; });
            df_json(['ok' => true, 'pin' => $pin, 'share' => df_share_public($h, $rec, $dek)]);
        }
        case 'share_list': {
            $doc = (string)($in['docId'] ?? '');
            $items = [];
            foreach (df_read('shares.json', []) as $h => $s) if ($doc === '' || ($s['doc'] ?? '') === $doc) $items[] = df_share_public((string)$h, $s, $dek);
            usort($items, fn($x, $y) => $y['created'] <=> $x['created']);
            df_json(['ok' => true, 'items' => $items]);
        }
        case 'share_del': { /* deactivate the link only; the stored file and the access log are kept */
            $h = (string)($in['id'] ?? '');
            if (!preg_match('/^[a-f0-9]{64}$/', $h)) df_json(['ok' => false, 'error' => 'bad id'], 400);
            df_update('shares.json', function (array &$all) use ($h) { if (isset($all[$h]) && empty($all[$h]['dead'])) { $all[$h]['dead'] = 'revoked'; $all[$h]['deadAt'] = time(); } });
            df_share_log($h, 'revoked', ['by' => $user]);
            df_json(['ok' => true]);
        }
        case 'share_log': {
            $h = (string)($in['id'] ?? '');
            if (!preg_match('/^[a-f0-9]{64}$/', $h)) df_json(['ok' => false, 'error' => 'bad id'], 400);
            df_json(['ok' => true, 'events' => df_share_log_read($h, $dek)]);
        }

        /* ---------- USD rate ---------- */
        case 'rate_get':
            df_rate_maybe_fetch(false);
            df_json(['ok' => true, 'fx' => df_rate_public()]);
        case 'rate_refresh': {
            $r = df_rate_maybe_fetch(true);
            $fx = df_rate_public();
            if ($r['status'] === 'ok') df_json(['ok' => true, 'fx' => $fx]);
            $msg = ['off' => 'دریافت نرخ از اینترنت خاموش است (تعداد دفعات در روز = ۰).',
                    'cap' => 'سقف دریافت نرخ دلار برای امروز (' . df_fa_num((string)$fx['perDay']) . ' بار) پر شده است.',
                    'fail' => 'نرخ دلار از اینترنت گرفته نشد. نرخ را دستی وارد کنید یا بعداً امتحان کنید.'][$r['status']] ?? 'خطا';
            df_json(['ok' => false, 'error' => $msg, 'fx' => $fx], $r['status'] === 'fail' ? 502 : 429);
        }
        case 'rate_set': {
            $v = (int)round((float)($in['rate'] ?? 0));
            if ($v < 1000 || $v > 1000000000) df_json(['ok' => false, 'error' => 'نرخ معتبر نیست.'], 400);
            df_update('rate.json', function (array &$r) use ($v, $user) { $r['rate'] = $v; $r['src'] = 'دستی (' . $user . ')'; $r['at'] = time() * 1000; $r['manual'] = true; }, []);
            df_json(['ok' => true, 'fx' => df_rate_public()]);
        }
        case 'rate_cfg': {
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر می‌تواند این را تغییر دهد.'], 403);
            $n = (int)($in['perDay'] ?? -1);
            if ($n < 0 || $n > 24) df_json(['ok' => false, 'error' => 'عددی بین ۰ تا ۲۴ وارد کنید.'], 400);
            df_update('rate.json', function (array &$r) use ($n) { $r['perDay'] = $n; }, []);
            df_json(['ok' => true, 'fx' => df_rate_public()]);
        }

        /* ---------- account & users ---------- */
        case 'pass_change': {
            $old = (string)($in['old'] ?? ''); $new = (string)($in['new'] ?? '');
            $u = df_users()[$user] ?? null;
            if (!$u || !password_verify($old, $u['hash'])) df_json(['ok' => false, 'error' => 'رمز فعلی اشتباه است.'], 400);
            if ($e = df_user_setpass($user, $new, $dek)) df_json(['ok' => false, 'error' => $e], 400);
            df_session_start(); $_SESSION['ver'] = (df_users()[$user]['ver'] ?? 1); session_write_close();
            df_json(['ok' => true]);
        }
        case 'users_list': {
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            $out = [];
            foreach (df_users() as $n => $u) $out[] = ['u' => $n, 'admin' => !empty($u['admin']), 'created' => ($u['created'] ?? 0) * 1000, 'keyed' => !empty($u['wk'])];
            $k = df_keys();
            df_json(['ok' => true, 'users' => $out, 'rcAt' => ($k['rkAt'] ?? 0) * 1000]);
        }
        case 'user_add': {
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            $e = df_user_add(trim((string)($in['u'] ?? '')), (string)($in['p'] ?? ''), !empty($in['admin']), $dek);
            if ($e) df_json(['ok' => false, 'error' => $e], 400);
            df_json(['ok' => true]);
        }
        case 'user_setpass': {
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            $n = (string)($in['u'] ?? '');
            if ($n === $user) df_json(['ok' => false, 'error' => 'رمز خودتان را از بخش «حساب کاربری» عوض کنید.'], 400);
            if ($e = df_user_setpass($n, (string)($in['p'] ?? ''), $dek)) df_json(['ok' => false, 'error' => $e], 400);
            df_json(['ok' => true]);
        }
        case 'user_del': {
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            $n = (string)($in['u'] ?? '');
            if ($n === $user) df_json(['ok' => false, 'error' => 'نمی‌توانید حساب خودتان را حذف کنید.'], 400);
            $e = df_update('users.json', function (array &$d) use ($n) {
                if (!isset($d['users'][$n])) return 'کاربر پیدا نشد.';
                $admins = array_filter($d['users'], fn($u) => !empty($u['admin']));
                if (!empty($d['users'][$n]['admin']) && count($admins) <= 1) return 'آخرین مدیر را نمی‌شود حذف کرد.';
                unset($d['users'][$n]);
                return null;
            }, ['users' => []]);
            if ($e) df_json(['ok' => false, 'error' => $e], 400);
            df_json(['ok' => true]);
        }
        case 'recovery_new': {
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            $u = df_users()[$user] ?? null;
            if (!$u || !password_verify((string)($in['p'] ?? ''), $u['hash'])) df_json(['ok' => false, 'error' => 'رمز عبور خودتان را درست وارد کنید.'], 400);
            df_json(['ok' => true, 'code' => df_rc_set($dek)]);
        }
        default:
            df_json(['ok' => false, 'error' => 'unknown action'], 400);
    }
} catch (InvalidArgumentException $e) {
    df_json(['ok' => false, 'error' => 'bad path'], 400);
} catch (Throwable $e) {
    error_log('daftar-factor api: ' . $e->getMessage());
    df_json(['ok' => false, 'error' => 'server error'], 500);
}
