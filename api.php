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

/* gallery upload: one raw 1 MB piece per request (no base64, stays under post_max_size), encrypted on arrival */
if (($_GET['a'] ?? '') === 'gal_chunk') {
    $id = (string)($_GET['id'] ?? ''); $i = (int)($_GET['i'] ?? -1);
    if (!gal_valid_id($id)) df_json(['ok' => false, 'error' => 'bad id'], 400);
    $bin = (string)file_get_contents('php://input', false, null, 0, GAL_CHUNK + 1);
    if ($e = gal_put_chunk($id, $i, $bin, $dek)) { $ns = strncmp($e, 'NOSPACE:', 8) === 0; df_json(['ok' => false, 'error' => $ns ? substr($e, 8) : $e, 'nospace' => $ns], $ns ? 507 : 400); }
    df_json(['ok' => true]);
}
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
            $pin = df_pin_norm((string)($in['pin'] ?? ''));
            if ($pin === '') $pin = str_pad((string)random_int(0, 99999), 5, '0', STR_PAD_LEFT);
            elseif (!preg_match('/^\d{4,5}$/', $pin)) df_json(['ok' => false, 'error' => 'رمز باید ۴ یا ۵ رقم باشد.'], 400);
            df_log_keys_ensure($dek);
            $t = df_b64u(random_bytes(16)); $h = df_share_hash($t); /* ۲۲ نویسه: در پیامک sms.ir (سقف ۲۵ نویسه برای هر پارامتر) جا می‌شود */
            df_write_atomic(df_share_file($h), df_enc($html, df_share_file_key($t, $pin, 1), 'share'));
            $title = mb_substr((string)($in['title'] ?? ''), 0, 160);
            $rec = ['doc' => $doc, 'created' => time(), 'by' => $user, 'exp' => $exp, 'max' => $max, 'used' => 0, 'fails' => 0, 'last' => 0,
                'pin' => password_hash($pin, PASSWORD_DEFAULT), 'pk' => 1, 'dead' => '',
                'te' => base64_encode(df_enc($t, $dek, 'tok')), 'tt' => base64_encode(df_enc($title, df_share_title_key($t), 'title')),
                'pe' => base64_encode(df_enc($pin, $dek, 'pin'))]; /* the PIN, readable only after login, so the sender can see it again */
            df_update('shares.json', function (array &$all) use ($h, $rec) { $all[$h] = $rec; });
            df_json(['ok' => true, 'pin' => $pin, 'share' => df_share_public($h, $rec, $dek)]);
        }
        case 'share_media': { /* one protected link for several catalog/gallery files — same rules as invoice links */
            $ids = array_values(array_filter(array_map('strval', (array)($in['ids'] ?? [])), 'gal_valid_id'));
            $title = mb_substr(trim((string)($in['title'] ?? '')), 0, 160) ?: 'فایل‌ها';
            $info = gal_clean_info($in['info'] ?? null);
            if ((!$ids && !$info) || count($ids) > 300) df_json(['ok' => false, 'error' => 'دست‌کم یک فایل انتخاب کنید.'], 400);
            $pack = gal_pack($ids, $title, $dek, $info);
            if (!$pack) df_json(['ok' => false, 'error' => 'فایل‌های انتخاب‌شده پیدا نشدند یا بارگذاری‌شان تمام نشده است.'], 400);
            $exp = (int)floor(((int)($in['exp'] ?? 0)) / 1000);
            if ($exp !== 0 && ($exp < time() + 60 || $exp > time() + 366 * 86400)) df_json(['ok' => false, 'error' => 'زمان انقضا معتبر نیست.'], 400);
            $max = max(0, min(10000, (int)($in['max'] ?? 0)));
            $pin = df_pin_norm((string)($in['pin'] ?? ''));
            if ($pin === '') $pin = str_pad((string)random_int(0, 99999), 5, '0', STR_PAD_LEFT);
            elseif (!preg_match('/^\d{4,5}$/', $pin)) df_json(['ok' => false, 'error' => 'رمز باید ۴ یا ۵ رقم باشد.'], 400);
            df_log_keys_ensure($dek);
            $t = df_b64u(random_bytes(16)); $h = df_share_hash($t);
            df_write_atomic(df_share_file($h), df_enc(json_encode($pack, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), df_share_file_key($t, $pin, 1), 'share'));
            $rec = ['doc' => 'gal', 'kind' => 'media', 'cnt' => count($pack['items']), 'created' => time(), 'by' => $user, 'exp' => $exp, 'max' => $max, 'used' => 0, 'fails' => 0, 'last' => 0,
                'pin' => password_hash($pin, PASSWORD_DEFAULT), 'pk' => 1, 'dead' => '',
                'te' => base64_encode(df_enc($t, $dek, 'tok')), 'tt' => base64_encode(df_enc($title, df_share_title_key($t), 'title')), 'pe' => base64_encode(df_enc($pin, $dek, 'pin'))];
            df_update('shares.json', function (array &$all) use ($h, $rec) { $all[$h] = $rec; });
            df_json(['ok' => true, 'pin' => $pin, 'share' => df_share_public($h, $rec, $dek)]);
        }

        /* ---------- catalogs & gallery (files encrypted in 1 MB pieces) ---------- */
        case 'gal_list':
            df_json(['ok' => true, 'items' => gal_public($dek)]);
        case 'gal_new': {
            $size = (int)($in['size'] ?? 0);
            if ($size <= 0) df_json(['ok' => false, 'error' => 'فایل خالی است.'], 400);
            if ($size > GAL_MAX) df_json(['ok' => false, 'error' => 'فایل بزرگ‌تر از ۱ گیگابایت است.'], 413);
            $sp = gal_space();
            if ($size > $sp['avail']) df_json(['ok' => false, 'error' => 'فضای کافی روی سرور نیست: این فایل ' . gal_fmt_size($size) . ' است و فقط ' . gal_fmt_size($sp['avail']) . ' جا مانده.', 'space' => $sp], 507);
            $id = gal_new(gal_clean_meta((array)($in['meta'] ?? [])), $size, $dek, $user);
            df_json(['ok' => true, 'id' => $id, 'chunk' => GAL_CHUNK]);
        }
        case 'gal_space':
            df_json(['ok' => true, 'space' => gal_space()]);
        case 'gal_status': { /* کدام تکه‌ها رسیده‌اند (برای ادامه‌ی بارگذاری قطع‌شده) */
            $id = (string)($in['id'] ?? ''); $it = gal_items()[$id] ?? null;
            if (!$it) df_json(['ok' => false, 'error' => 'این بارگذاری روی سرور پیدا نشد (شاید پاک شده باشد).'], 404);
            df_json(['ok' => true, 'have' => gal_have($id), 'chunks' => (int)$it['chunks'], 'size' => (int)$it['size'], 'done' => !empty($it['done']), 'chunk' => GAL_CHUNK]);
        }
        case 'gal_done': {
            $id = (string)($in['id'] ?? '');
            if (!gal_valid_id($id)) df_json(['ok' => false, 'error' => 'bad id'], 400);
            if ($e = gal_finish($id)) df_json(['ok' => false, 'error' => $e], 400);
            df_json(['ok' => true]);
        }
        case 'gal_thumb': {
            $id = (string)($in['id'] ?? ''); $bin = base64_decode((string)($in['data'] ?? ''), true);
            if (!gal_valid_id($id) || !$bin || strlen($bin) > 600000) df_json(['ok' => false, 'error' => 'bad thumb'], 400);
            gal_put_thumb($id, $bin, $dek);
            df_json(['ok' => true]);
        }
        case 'gal_edit': {
            $id = (string)($in['id'] ?? ''); $it = gal_items()[$id] ?? null;
            if (!$it) df_json(['ok' => false, 'error' => 'فایل پیدا نشد.'], 404);
            gal_set_meta($id, gal_clean_meta((array)($in['meta'] ?? []), gal_meta($it, $dek)), $dek);
            df_json(['ok' => true]);
        }
        case 'gal_del': {
            foreach ((array)($in['ids'] ?? []) as $id) if (gal_valid_id((string)$id)) gal_delete((string)$id);
            df_json(['ok' => true]);
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

        /* ---------- QR تأیید اصالت (inc/verify.php) ---------- */
        case 'vf_put': {
            $t = (string)($in['tok'] ?? ''); $doc = (string)($in['docId'] ?? '');
            if (!vf_valid_token($t) || $doc === '' || strlen($doc) > 64) df_json(['ok' => false, 'error' => 'bad input'], 400);
            $html = isset($in['html']) ? (string)$in['html'] : null;
            if ($html !== null && ($html === '' || strlen($html) > 8 * 1024 * 1024)) df_json(['ok' => false, 'error' => 'bad input'], 400);
            df_log_keys_ensure($dek);
            $r = vf_put($t, $doc, $html, trim((string)($in['name'] ?? '')), (string)($in['mobile'] ?? ''), !empty($in['dead']), $user, !empty($in['sign']));
            if (!$r['ok']) df_json($r, 409);
            df_json(['ok' => true, 'vf' => vf_public($r['id'], vf_all()[$r['id']] ?? []), 'sms' => sms_ready()]);
        }
        case 'vf_info': {
            $t = (string)($in['tok'] ?? '');
            if (!vf_valid_token($t)) df_json(['ok' => false, 'error' => 'bad input'], 400);
            $h = vf_hash($t); $r = vf_all()[$h] ?? null;
            df_json(['ok' => true, 'vf' => $r ? vf_public($h, $r) : null, 'events' => $r && !empty($in['log']) ? df_share_log_read($h, $dek) : []]);
        }

        case 'share_sms': { /* لینک (و اگر خواستید رمز) با پیامک الگو برای مشتری */
            $h = (string)($in['id'] ?? '');
            $sh = df_read('shares.json', [])[$h] ?? null;
            if (!$sh) df_json(['ok' => false, 'error' => 'لینک پیدا نشد.'], 404);
            $t = !empty($sh['te']) ? df_dec((string)base64_decode($sh['te']), $dek, 'tok') : null;
            if (!$t) df_json(['ok' => false, 'error' => 'لینک خوانده نشد.'], 400);
            if (strlen($t) > 25) df_json(['ok' => false, 'error' => 'این لینک قدیمی است و برای پیامک بلند است؛ یک لینک تازه بسازید.'], 400);
            $withPin = !empty($in['pin']);
            $pin = !empty($sh['pe']) ? (string)df_dec((string)base64_decode($sh['pe']), $dek, 'pin') : '';
            if ($withPin && $pin === '') df_json(['ok' => false, 'error' => 'رمز این لینک ذخیره نشده است.'], 400);
            $r = sms_send((string)($in['mobile'] ?? ''), $withPin ? 'link_pin' : 'link', $withPin ? ['LINK' => $t, 'PIN' => $pin] : ['LINK' => $t], 'لینک فایل · ' . $user);
            if ($r['ok']) df_share_log($h, 'sms', ['to' => sms_mask(sms_mobile((string)($in['mobile'] ?? ''))), 'pin' => $withPin ? 1 : 0, 'by' => $user, 'test' => !empty($r['test']) ? 1 : 0]);
            df_json(['ok' => $r['ok'], 'error' => $r['ok'] ? '' : $r['msg'], 'msg' => $r['msg']], $r['ok'] ? 200 : 502);
        }

        /* ---------- accounting attachments (customer/order dossier files), encrypted with the data key ---------- */
        case 'att_put': {
            $id = (string)($in['id'] ?? '');
            if (!preg_match('/^[a-z0-9]{6,40}$/', $id)) df_json(['ok' => false, 'error' => 'bad id'], 400);
            $bin = base64_decode((string)($in['data'] ?? ''), true);
            if ($bin === false || $bin === '') df_json(['ok' => false, 'error' => 'فایل خالی است.'], 400);
            if (strlen($bin) > 8 * 1024 * 1024) df_json(['ok' => false, 'error' => 'فایل بزرگ‌تر از ۸ مگابایت است.'], 413);
            df_swrite(df_att_path($id, $dek), $bin, $dek, 'att');
            df_json(['ok' => true]);
        }
        case 'att_get': {
            $id = (string)($in['id'] ?? '');
            if (!preg_match('/^[a-z0-9]{6,40}$/', $id)) df_json(['ok' => false, 'error' => 'bad id'], 400);
            $bin = df_sread(df_att_path($id, $dek), $dek, 'att');
            if ($bin === null) df_json(['ok' => false, 'error' => 'فایل روی سرور پیدا نشد.'], 404);
            df_json(['ok' => true, 'data' => base64_encode($bin)]);
        }
        case 'att_del': {
            $id = (string)($in['id'] ?? '');
            if (preg_match('/^[a-z0-9]{6,40}$/', $id)) @unlink(df_path(df_att_path($id, $dek)));
            df_json(['ok' => true]);
        }

        /* ---------- my account: fingerprint, trusted devices, mobile ---------- */
        case 'sec_get':
            df_json(['ok' => true, 'sec' => df_dev_public($user), 'rp' => pk_rp_id(), 'https' => df_is_https(), 'smsLogin' => !empty(sms_cfg()['login'])]);
        case 'pk_reg_options':
            df_session_start(); $o = pk_reg_options($user, !empty($in['compat'])); session_write_close();
            df_json(['ok' => true, 'options' => $o]);
        case 'pk_reg_verify': {
            df_session_start(); $e = pk_reg_verify($user, $dek, (array)($in['cred'] ?? [])); session_write_close();
            if ($e) df_json(['ok' => false, 'error' => $e], 400);
            df_json(['ok' => true, 'sec' => df_dev_public($user)]);
        }
        case 'pk_del':
            df_pk_remove($user, (string)($in['id'] ?? ''));
            df_json(['ok' => true, 'sec' => df_dev_public($user)]);
        case 'dev_sms': { /* ورود با پیامک روی همین دستگاه */
            if (!empty($in['on'])) {
                if (sms_mobile((string)(df_users()[$user]['mobile'] ?? '')) === '') df_json(['ok' => false, 'error' => 'اول شماره‌ی موبایل خودتان را ثبت کنید.'], 400);
                df_dev_ensure($user, $dek, ['sms' => true]);
            } elseif (($did = df_dev_id()) !== '') {
                df_update('users.json', function (array &$d) use ($user, $did) {
                    if (!isset($d['users'][$user]['devs'][$did])) return;
                    $d['users'][$user]['devs'][$did]['sms'] = false;
                    if (empty($d['users'][$user]['devs'][$did]['pk'])) unset($d['users'][$user]['devs'][$did]);
                }, ['users' => []]);
            }
            df_json(['ok' => true, 'sec' => df_dev_public($user)]);
        }
        case 'dev_del':
            df_dev_remove($user, (string)($in['id'] ?? ''));
            df_json(['ok' => true, 'sec' => df_dev_public($user)]);
        case 'me_mobile': {
            $m = trim((string)($in['mobile'] ?? ''));
            $mm = $m === '' ? '' : sms_mobile($m);
            if ($m !== '' && $mm === '') df_json(['ok' => false, 'error' => 'شماره‌ی موبایل درست نیست (مثلاً ۰۹۱۲۱۲۳۴۵۶۷).'], 400);
            df_update('users.json', function (array &$d) use ($user, $mm) { if (isset($d['users'][$user])) $d['users'][$user]['mobile'] = $mm; }, ['users' => []]);
            df_json(['ok' => true, 'sec' => df_dev_public($user)]);
        }

        /* ---------- SMS settings (sms.ir) ---------- */
        case 'sms_get': {
            $c = sms_cfg(); $k = (string)$c['key'];
            df_json(['ok' => true, 'sms' => ['hasKey' => $k !== '', 'keyTail' => $k !== '' ? substr($k, -4) : '', 'keyInConfig' => defined('DF_SMSIR_KEY') && DF_SMSIR_KEY !== '',
                'tpl' => (object)$c['tpl'], 'login' => !empty($c['login']), 'test' => !empty($c['test']), 'base' => df_base_url(), 'tpls' => DF_SMS_TPLS]]);
        }
        case 'sms_set': {
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            df_update('sms.json', function (array &$c) use ($in) {
                if (isset($in['key']) && trim((string)$in['key']) !== '') $c['key'] = trim((string)$in['key']);
                if (!empty($in['clearKey'])) $c['key'] = '';
                foreach (array_keys(DF_SMS_TPLS) as $k) if (isset($in['tpl'][$k])) $c['tpl'][$k] = max(0, (int)df_fa_digits((string)$in['tpl'][$k]));
                if (isset($in['login'])) $c['login'] = (bool)$in['login'];
                if (isset($in['test'])) $c['test'] = (bool)$in['test'];
            });
            df_json(['ok' => true]);
        }
        case 'sms_test': {
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            $k = (string)($in['tpl'] ?? 'otp');
            if (!isset(DF_SMS_TPLS[$k])) df_json(['ok' => false, 'error' => 'الگو نامعتبر است.'], 400);
            $vals = ['CODE' => '12345', 'VERIFICATIONCODE' => '#12345', 'LINK' => 'TEST-link-123', 'PIN' => '54321'];
            $r = sms_send((string)($in['mobile'] ?? ''), $k, array_intersect_key($vals, array_flip(DF_SMS_TPLS[$k][1])), 'آزمایش · ' . $user);
            df_json(['ok' => $r['ok'], 'error' => $r['ok'] ? '' : $r['msg'], 'msg' => $r['msg']], $r['ok'] ? 200 : 502);
        }
        /* ---------- ایمیل و پیامک نامه‌ها ---------- */
        case 'mail_get': {
            if (!df_perm('letters')) df_json(['ok' => false, 'error' => 'دسترسی ندارید'], 403);
            $c = mail_cfg($dek);
            df_json(['ok' => true, 'mail' => ['host' => $c['host'], 'port' => (int)$c['port'], 'sec' => $c['sec'], 'user' => $c['user'], 'hasPass' => $c['pass'] !== '', 'from' => $c['from'], 'name' => $c['name'], 'reply' => $c['reply']]]);
        }
        case 'mail_set': {
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            $c = mail_cfg($dek);
            foreach (['host', 'user', 'name', 'reply'] as $k) if (isset($in[$k])) $c[$k] = trim((string)$in[$k]);
            if (isset($in['port'])) $c['port'] = max(1, min(65535, (int)$in['port']));
            if (isset($in['sec']) && in_array($in['sec'], ['ssl', 'tls', 'none'], true)) $c['sec'] = $in['sec'];
            if (isset($in['from'])) { $f = trim((string)$in['from']); if ($f !== '' && !mail_valid($f)) df_json(['ok' => false, 'error' => 'نشانی فرستنده درست نیست.'], 400); $c['from'] = $f; }
            if (isset($in['pass']) && (string)$in['pass'] !== '') $c['pass'] = (string)$in['pass'];
            if (!empty($in['clearPass'])) $c['pass'] = '';
            mail_cfg_save($c, $dek);
            df_json(['ok' => true]);
        }
        case 'mail_send': {
            if (!df_perm('letters')) df_json(['ok' => false, 'error' => 'دسترسی ندارید'], 403);
            $c = mail_cfg($dek);
            $to = mail_parse_addrs((string)($in['to'] ?? '')); $cc = mail_parse_addrs((string)($in['cc'] ?? ''));
            if (!$to) df_json(['ok' => false, 'error' => 'نشانی ایمیل گیرنده درست نیست.'], 400);
            $html = (string)($in['html'] ?? ''); if ($html === '' || strlen($html) > 6 * 1024 * 1024) df_json(['ok' => false, 'error' => 'متن ایمیل خالی یا بسیار بزرگ است.'], 400);
            $att = [];
            if (!empty($in['attachName'])) $att[] = ['name' => mb_substr((string)$in['attachName'], 0, 120), 'mime' => 'text/html; charset=UTF-8', 'data' => $html];
            $subject = mb_substr(trim((string)($in['subject'] ?? '')), 0, 200);
            $data = mail_build($c, $to, $cc, $subject, $html, $att);
            $r = mail_smtp($c, array_merge(array_column($to, 'email'), array_column($cc, 'email')), $data);
            df_json(['ok' => $r['ok'], 'error' => $r['ok'] ? '' : $r['msg'], 'msg' => $r['msg']], $r['ok'] ? 200 : 502);
        }
        case 'letter_sms': { /* لینک تأیید/دیدن نامه (QR) را با پیامک برای گیرنده یا رونوشت می‌فرستد */
            if (!df_perm('letters')) df_json(['ok' => false, 'error' => 'دسترسی ندارید'], 403);
            $t = (string)($in['tok'] ?? '');
            if (!vf_valid_token($t) || !isset(vf_all()[vf_hash($t)])) df_json(['ok' => false, 'error' => 'این نامه هنوز نهایی و روی سرور ثبت نشده است.'], 404);
            $r = sms_send((string)($in['mobile'] ?? ''), 'letter', ['LINK' => $t], 'لینک نامه · ' . $user);
            df_json(['ok' => $r['ok'], 'error' => $r['ok'] ? '' : $r['msg'], 'msg' => $r['msg']], $r['ok'] ? 200 : 502);
        }
        case 'contract_sms': { /* لینک امضای قرارداد را برای کارمند پیامک می‌کند */
            if (!df_perm('hr')) df_json(['ok' => false, 'error' => 'دسترسی ندارید'], 403);
            $t = (string)($in['tok'] ?? '');
            $rec = vf_valid_token($t) ? (vf_all()[vf_hash($t)] ?? null) : null;
            if (!$rec || empty($rec['sign'])) df_json(['ok' => false, 'error' => 'این قرارداد هنوز برای امضا روی سرور ثبت نشده است.'], 404);
            $r = sms_send((string)($in['mobile'] ?? ''), 'contract', ['LINK' => $t], 'امضای قرارداد · ' . $user);
            df_json(['ok' => $r['ok'], 'error' => $r['ok'] ? '' : $r['msg'], 'msg' => $r['msg']], $r['ok'] ? 200 : 502);
        }
        case 'user_perms': { /* مدیر برای هر کاربر تعیین می‌کند کدام بخش‌ها را ببیند (null = همه) */
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            $n = (string)($in['u'] ?? ''); $p = $in['perms'] ?? null;
            $p = is_array($p) ? array_values(array_intersect(array_map('strval', $p), DF_PERMS)) : null;
            $e = df_update('users.json', function (array &$d) use ($n, $p) { if (!isset($d['users'][$n])) return 'کاربر پیدا نشد.'; if ($p === null) unset($d['users'][$n]['perms']); else $d['users'][$n]['perms'] = $p; return null; }, ['users' => []]);
            if ($e) df_json(['ok' => false, 'error' => $e], 400);
            df_json(['ok' => true]);
        }

        case 'sms_log':
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            df_json(['ok' => true, 'items' => sms_log_read($dek)]);

        /* ---------- central printing (print stations) ---------- */
        case 'ps_list':
            df_json(['ok' => true, 'stations' => prn_stations_public($dek), 'jobs' => prn_jobs_public($dek, (int)($in['limit'] ?? 40)), 'agent' => prn_exe_info()]);
        case 'ps_agent': /* fetch the ready-made Windows program from GitHub now (also done automatically on download) */
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            prn_exe(true);
            df_json(['ok' => true, 'agent' => prn_exe_info()]);
        case 'ps_add': {
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            [$sid] = prn_station_add((string)($in['name'] ?? ''), $dek, $user);
            df_json(['ok' => true, 'id' => $sid, 'stations' => prn_stations_public($dek)]);
        }
        case 'ps_del':
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            prn_station_del((string)($in['id'] ?? ''));
            df_json(['ok' => true, 'stations' => prn_stations_public($dek)]);
        case 'pj_send': {
            $sid = (string)($in['sid'] ?? '');
            if (!isset(prn_stations()[$sid])) df_json(['ok' => false, 'error' => 'ایستگاه چاپ پیدا نشد.'], 404);
            $html = (string)($in['html'] ?? '');
            if ($html === '' || strlen($html) > 12 * 1024 * 1024) df_json(['ok' => false, 'error' => 'محتوای چاپ خالی یا خیلی بزرگ است.'], 400);
            $id = prn_job_add($sid, (array)($in['meta'] ?? []), $html, $dek, $user);
            df_json(['ok' => true, 'id' => $id]);
        }
        case 'pj_retry':
            $id = (string)($in['id'] ?? '');
            if (!is_file(prn_blob($id))) df_json(['ok' => false, 'error' => 'محتوای این کار دیگر روی سرور نیست (کارهای چاپ‌شده پاک می‌شوند)؛ دوباره از خود سند چاپ بزنید.'], 410);
            prn_job_set($id, function (array &$x) { $x['st'] = 'queued'; $x['tries'] = 0; $x['err'] = ''; $x['at'] = time(); });
            df_json(['ok' => true]);
        case 'pj_cancel': {
            $id = (string)($in['id'] ?? '');
            prn_job_set($id, function (array &$x) { if (in_array($x['st'], ['queued', 'claimed', 'error'], true)) { $x['st'] = 'canceled'; $x['done'] = time(); } });
            @unlink(prn_blob($id));
            df_json(['ok' => true]);
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
            foreach (df_users() as $n => $u) $out[] = ['u' => $n, 'admin' => !empty($u['admin']), 'created' => ($u['created'] ?? 0) * 1000, 'keyed' => !empty($u['wk']),
                'mobile' => (string)($u['mobile'] ?? ''), 'perms' => $u['perms'] ?? null, 'smsDevs' => count(array_filter((array)($u['devs'] ?? []), fn($x) => !empty($x['sms'])))];
            $k = df_keys();
            df_json(['ok' => true, 'users' => $out, 'rcAt' => ($k['rkAt'] ?? 0) * 1000]);
        }
        case 'user_add': {
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            $m = trim((string)($in['mobile'] ?? '')); $mm = $m === '' ? '' : sms_mobile($m);
            if ($m !== '' && $mm === '') df_json(['ok' => false, 'error' => 'شماره‌ی موبایل درست نیست (مثلاً ۰۹۱۲۱۲۳۴۵۶۷).'], 400);
            $nu = trim((string)($in['u'] ?? ''));
            $e = df_user_add($nu, (string)($in['p'] ?? ''), !empty($in['admin']), $dek);
            if ($e) df_json(['ok' => false, 'error' => $e], 400);
            if ($mm !== '') df_update('users.json', function (array &$d) use ($nu, $mm) { if (isset($d['users'][$nu])) $d['users'][$nu]['mobile'] = $mm; }, ['users' => []]);
            df_json(['ok' => true]);
        }
        case 'user_mobile': { /* مدیر شماره‌ی موبایل هر کاربر را ثبت می‌کند (برای ورود پیامکی) */
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            $n = (string)($in['u'] ?? ''); $m = trim((string)($in['mobile'] ?? '')); $mm = $m === '' ? '' : sms_mobile($m);
            if ($m !== '' && $mm === '') df_json(['ok' => false, 'error' => 'شماره‌ی موبایل درست نیست (مثلاً ۰۹۱۲۱۲۳۴۵۶۷).'], 400);
            $e = df_update('users.json', function (array &$d) use ($n, $mm) { if (!isset($d['users'][$n])) return 'کاربر پیدا نشد.'; $d['users'][$n]['mobile'] = $mm; return null; }, ['users' => []]);
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
        /* ---------- updates from GitHub ---------- */
        case 'update_status':
            df_json(['ok' => true, 'upd' => df_upd_status()]);
        case 'update_tick': { /* called periodically by open pages; installs automatically when enabled */
            $st = df_upd_state();
            $r = df_upd_run(false, (bool)$st['auto'], 'auto');
            df_json(['ok' => true, 'r' => $r, 'upd' => df_upd_status()]);
        }
        case 'update_check':
        case 'update_apply': {
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            $r = df_upd_run(true, $a === 'update_apply', $user);
            df_json(['ok' => empty($r['error']), 'error' => $r['error'] ?? '', 'r' => $r, 'upd' => df_upd_status()], empty($r['error']) ? 200 : 502);
        }
        case 'update_cfg': {
            if (!$admin) df_json(['ok' => false, 'error' => 'فقط مدیر'], 403);
            $auto = !empty($in['auto']); $every = max(5, min(1440, (int)($in['every'] ?? 10)));
            df_update('update.json', function (array &$s) use ($auto, $every) { $s['auto'] = $auto; $s['every'] = $every; }, []);
            df_json(['ok' => true, 'upd' => df_upd_status()]);
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
