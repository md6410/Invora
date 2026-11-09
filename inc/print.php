<?php
/* دفتر فاکتور — چاپگر مرکزی (ایستگاه چاپ)

   مثل وبی: برنامه‌ی پایتونیِ print-agent روی کامپیوتر دفتر هر چند ثانیه از سایت می‌پرسد «کار چاپی داری؟»؛
   پس هیچ پورتی باز نمی‌شود و IP ثابت لازم نیست. اگر اینترنت قطع شود، کارها در صف می‌مانند.

   امنیت صف:
   - توکن هر ایستگاه فقط به‌صورت هش (برای شناسایی) و رمزشده با کلید داده (برای نمایش دوباره به مدیر) ذخیره می‌شود؛
   - محتوای هر کار (HTML سند یا برچسب و عنوانش) با کلیدی رمز می‌شود که از توکن همان ایستگاه ساخته می‌شود.
     سایت این کلید را فقط در لحظه‌ی ساخت کار (بعد از ورود کاربر) دارد؛ ایستگاه با توکن خودش بازش می‌کند.
     پس فایل‌های صف روی هاست بدون توکن و بدون کلید داده خوانا نیستند. */
declare(strict_types=1);
if (!defined('DF')) { http_response_code(403); exit; }

const DF_PRN_KEEP = 300;

function prn_hash(string $tok): string { return hash('sha256', 'df-print:' . $tok); }
function prn_job_key(string $tok): string { return hash_hmac('sha256', 'df-print-job', $tok, true); }
function prn_blob(string $id): string { return df_path('print-jobs/' . $id . '.bin'); }
function prn_stations(): array { return df_read('print.json', ['stations' => []])['stations'] ?? []; }

function prn_station_add(string $name, string $dek, string $user): array {
    $tok = df_b64u(random_bytes(24)); $sid = bin2hex(random_bytes(6));
    $rec = ['name' => mb_substr(trim($name) ?: 'ایستگاه', 0, 60), 'th' => prn_hash($tok), 'te' => base64_encode(df_enc($tok, $dek, 'ptok')),
        'created' => time(), 'by' => $user, 'seen' => 0, 'printers' => [], 'ver' => '', 'host' => ''];
    df_update('print.json', function (array &$d) use ($sid, $rec) { $d['stations'][$sid] = $rec; }, ['stations' => []]);
    return [$sid, $tok];
}
function prn_station_token(string $sid, string $dek): ?string {
    $s = prn_stations()[$sid] ?? null;
    return $s ? df_dec((string)base64_decode((string)$s['te']), $dek, 'ptok') : null;
}
function prn_stations_public(string $dek): array {
    $out = [];
    foreach (prn_stations() as $sid => $s) $out[] = ['id' => $sid, 'name' => $s['name'], 'token' => (string)(df_dec((string)base64_decode((string)$s['te']), $dek, 'ptok') ?? ''),
        'seen' => ($s['seen'] ?? 0) * 1000, 'online' => ($s['seen'] ?? 0) > time() - 60, 'printers' => $s['printers'] ?? [], 'ver' => $s['ver'] ?? '', 'host' => $s['host'] ?? '', 'created' => ($s['created'] ?? 0) * 1000];
    return $out;
}
function prn_station_del(string $sid): void {
    df_update('print.json', function (array &$d) use ($sid) { unset($d['stations'][$sid]); }, ['stations' => []]);
    df_update('print-jobs.json', function (array &$j) use ($sid) {
        foreach ($j as $k => $x) if (($x['sid'] ?? '') === $sid) { @unlink(prn_blob((string)$k)); unset($j[$k]); }
    });
}

/* ---------- کارها ---------- */
function prn_job_add(string $sid, array $m, string $html, string $dek, string $user): string {
    $tok = prn_station_token($sid, $dek);
    if ($tok === null) throw new RuntimeException('ایستگاه پیدا نشد.');
    $id = bin2hex(random_bytes(8));
    $title = mb_substr((string)($m['title'] ?? ''), 0, 160);
    df_write_atomic(prn_blob($id), df_enc(json_encode(['title' => $title, 'html' => $html], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), prn_job_key($tok), 'pjob'));
    $rec = ['sid' => $sid, 'st' => 'queued', 'tt' => base64_encode(df_enc($title, $dek, 'ptitle')), 'printer' => mb_substr((string)($m['printer'] ?? ''), 0, 120),
        'w' => round((float)($m['w'] ?? 0), 1), 'h' => round((float)($m['h'] ?? 0), 1), 'copies' => max(1, min(50, (int)($m['copies'] ?? 1))),
        'kind' => in_array($m['kind'] ?? '', ['doc', 'label', 'test'], true) ? $m['kind'] : 'doc', 'pages' => max(1, (int)($m['pages'] ?? 1)),
        'at' => time(), 'by' => $user, 'tries' => 0, 'err' => ''];
    df_update('print-jobs.json', function (array &$j) use ($id, $rec) {
        $j[$id] = $rec;
        if (count($j) > DF_PRN_KEEP) {
            uasort($j, fn($a, $b) => ($a['at'] ?? 0) <=> ($b['at'] ?? 0));
            foreach (array_slice(array_keys($j), 0, count($j) - DF_PRN_KEEP) as $k) { @unlink(prn_blob((string)$k)); unset($j[$k]); }
        }
    });
    return $id;
}
function prn_jobs_public(string $dek, int $limit = 60): array {
    $j = df_read('print-jobs.json', []); $st = prn_stations(); $out = [];
    uasort($j, fn($a, $b) => ($b['at'] ?? 0) <=> ($a['at'] ?? 0));
    foreach (array_slice($j, 0, $limit, true) as $id => $x)
        $out[] = ['id' => $id, 'sid' => $x['sid'], 'station' => $st[$x['sid']]['name'] ?? '—', 'st' => $x['st'], 'title' => (string)(df_dec((string)base64_decode((string)($x['tt'] ?? '')), $dek, 'ptitle') ?? ''),
            'printer' => $x['printer'], 'w' => $x['w'], 'h' => $x['h'], 'copies' => $x['copies'], 'kind' => $x['kind'], 'at' => $x['at'] * 1000, 'by' => $x['by'],
            'done' => ($x['done'] ?? 0) * 1000, 'err' => $x['err'] ?? ''];
    return $out;
}
function prn_job_set(string $id, callable $fn): bool {
    return (bool)df_update('print-jobs.json', function (array &$j) use ($id, $fn) { if (!isset($j[$id])) return false; $fn($j[$id]); return true; });
}

/* ---------- سمت ایستگاه ---------- */
function prn_station_by_token(string $tok): ?string {
    if (!preg_match('/^[A-Za-z0-9_-]{20,64}$/', $tok)) return null;
    $h = prn_hash($tok);
    foreach (prn_stations() as $sid => $s) if (hash_equals((string)$s['th'], $h)) return (string)$sid;
    return null;
}
function prn_hello(string $sid, array $printers, string $ver, string $host): void {
    $clean = [];
    foreach (array_slice($printers, 0, 30) as $p) {
        if (!is_array($p) || trim((string)($p['name'] ?? '')) === '') continue;
        $clean[] = ['name' => mb_substr(trim((string)$p['name']), 0, 120), 'paper' => mb_substr((string)($p['paper'] ?? ''), 0, 60),
            'w' => (float)($p['w'] ?? 0), 'h' => (float)($p['h'] ?? 0), 'kind' => ($p['kind'] ?? '') === 'thermal' ? 'thermal' : 'paper', 'default' => !empty($p['default'])];
    }
    df_update('print.json', function (array &$d) use ($sid, $clean, $ver, $host) {
        if (!isset($d['stations'][$sid])) return;
        $d['stations'][$sid]['printers'] = $clean; $d['stations'][$sid]['ver'] = mb_substr($ver, 0, 20);
        $d['stations'][$sid]['host'] = mb_substr($host, 0, 60); $d['stations'][$sid]['seen'] = time();
    }, ['stations' => []]);
}
function prn_seen(string $sid): void {
    $s = prn_stations()[$sid] ?? null;
    if ($s && ($s['seen'] ?? 0) < time() - 20) df_update('print.json', function (array &$d) use ($sid) { if (isset($d['stations'][$sid])) $d['stations'][$sid]['seen'] = time(); }, ['stations' => []]);
}
/* کار بعدی؛ کاری که «گرفته شد» ولی چاپش شروع نشد بعد از ۵ دقیقه به صف برمی‌گردد،
   ولی کاری که چاپش شروع شده دوباره چاپ نمی‌شود (ممکن است روی کاغذ آمده باشد) و به خطا می‌رود — مثل وبی. */
function prn_claim(string $sid): ?array {
    prn_seen($sid);
    return df_update('print-jobs.json', function (array &$j) use ($sid) {
        $now = time(); $next = null;
        foreach ($j as $id => &$x) {
            if (($x['sid'] ?? '') !== $sid) continue;
            if ($x['st'] === 'claimed' && ($x['claimed'] ?? 0) < $now - 300) {
                if (($x['tries'] ?? 0) < 3) $x['st'] = 'queued';
                else { $x['st'] = 'error'; $x['err'] = 'ایستگاه کار را سه بار گرفت و نتیجه را اعلام نکرد.'; $x['done'] = $now; }
            }
            if ($x['st'] === 'printing' && ($x['printing'] ?? 0) < $now - 1200) { $x['st'] = 'error'; $x['err'] = 'ایستگاه نتیجه‌ی چاپ را اعلام نکرد؛ اگر روی کاغذ نیامده «دوباره» را بزنید.'; $x['done'] = $now; }
        }
        unset($x);
        $ids = array_keys(array_filter($j, fn($x) => ($x['sid'] ?? '') === $sid && $x['st'] === 'queued'));
        usort($ids, fn($a, $b) => ($j[$a]['at'] ?? 0) <=> ($j[$b]['at'] ?? 0));
        foreach ($ids as $id) {
            if (!is_file(prn_blob((string)$id))) { $j[$id]['st'] = 'error'; $j[$id]['err'] = 'فایل کار پیدا نشد.'; continue; }
            $j[$id]['st'] = 'claimed'; $j[$id]['claimed'] = $now; $j[$id]['tries'] = ($j[$id]['tries'] ?? 0) + 1;
            $x = $j[$id];
            $next = ['id' => (string)$id, 'printer' => $x['printer'], 'w' => $x['w'], 'h' => $x['h'], 'copies' => $x['copies'], 'kind' => $x['kind'],
                'blob' => base64_encode((string)file_get_contents(prn_blob((string)$id)))];
            break;
        }
        return $next;
    });
}
function prn_status(string $sid, string $id, string $st, string $err): bool {
    if (!in_array($st, ['printing', 'done', 'error'], true)) return false;
    $ok = (bool)df_update('print-jobs.json', function (array &$j) use ($sid, $id, $st, $err) {
        if (!isset($j[$id]) || $j[$id]['sid'] !== $sid) return false;
        $j[$id]['st'] = $st;
        if ($st === 'printing') $j[$id]['printing'] = time();
        else { $j[$id]['done'] = time(); $j[$id]['err'] = mb_substr($err, 0, 400); }
        return true;
    });
    if ($ok && $st === 'done') @unlink(prn_blob($id)); /* چاپ شد؛ محتوا دیگر روی سرور نمی‌ماند */
    return $ok;
}

/* ---------- بسته‌ی نصب برنامه‌ی ایستگاه (ZIP، با نشانی سایت و توکن آماده) ----------
   نسخه‌ی اصلی، برنامه‌ی آماده‌ی ویندوز است (InvoraPrint.exe: پایتون و همه‌ی کتابخانه‌ها داخلش) که GitHub Actions
   روی ویندوز می‌سازد و می‌آزماید و در Release «print-agent» می‌گذارد. سایت آن را یک بار می‌گیرد و نگه می‌دارد
   (هر ۶ ساعت نسخه‌اش را می‌سنجد)؛ پس نصب روی کامپیوتر دفتر به اینترنت و پایتون نیازی ندارد. */
function prn_exe(bool $force = false): ?array {
    $dir = df_path('agent-bin'); $exe = $dir . '/InvoraPrint.exe';
    $meta = df_read('agent-bin.json', []);
    if ($force || !is_file($exe) || (int)($meta['checked'] ?? 0) < time() - 6 * 3600) {
        $base = DF_GH_WEB . '/' . DF_UPDATE_REPO . '/releases/download/print-agent/';
        [$c, $v] = df_http($base . 'version.txt', 20);
        $v = trim((string)$v);
        if ($c === 200 && preg_match('/^[0-9][\w.\- ]{0,80}$/', $v) && ($v !== ($meta['ver'] ?? '') || !is_file($exe))) {
            @set_time_limit(300);
            [$c2, $b] = df_http($base . 'InvoraPrint.exe', 280);
            if ($c2 === 200 && strlen($b) > 1000000 && strncmp($b, 'MZ', 2) === 0) { df_write_atomic($exe, $b); $meta['ver'] = $v; $meta['size'] = strlen($b); $meta['at'] = time(); }
            else $meta['err'] = 'دانلود فایل برنامه از گیت‌هاب نشد (کد ' . $c2 . ').';
        } elseif ($c !== 200) $meta['err'] = 'نسخه‌ی برنامه از گیت‌هاب خوانده نشد (کد ' . $c . ').';
        if (is_file($exe) && ($meta['ver'] ?? '') === $v) unset($meta['err']);
        $meta['checked'] = time();
        df_write('agent-bin.json', $meta);
    }
    return is_file($exe) ? ['path' => $exe, 'ver' => (string)($meta['ver'] ?? ''), 'size' => (int)filesize($exe)] : null;
}
function prn_exe_info(): array { $m = df_read('agent-bin.json', []); $exe = df_path('agent-bin/InvoraPrint.exe'); return ['ready' => is_file($exe), 'ver' => (string)($m['ver'] ?? ''), 'size' => is_file($exe) ? (int)filesize($exe) : 0, 'err' => (string)($m['err'] ?? ''), 'checked' => (int)($m['checked'] ?? 0) * 1000]; }
function prn_agent_files(): array {
    $dir = df_app_root() . '/print-agent';
    $out = [];
    foreach (['agent.py', 'requirements.txt', 'README.md', 'install-windows.bat', 'run-windows.bat'] as $f) if (is_file("$dir/$f")) $out[$f] = (string)file_get_contents("$dir/$f");
    return $out;
}
function prn_zip(array $files): string {
    $data = ''; $cd = ''; $n = 0; $t = getdate();
    $dt = (($t['year'] - 1980) << 25) | ($t['mon'] << 21) | ($t['mday'] << 16) | ($t['hours'] << 11) | ($t['minutes'] << 5) | intdiv($t['seconds'], 2);
    foreach ($files as $name => $body) {
        $name = 'invora-print/' . $name; $crc = crc32($body); $len = strlen($body); $off = strlen($data);
        $store = !function_exists('gzdeflate') || strlen($body) > 4 * 1048576;   /* the big .exe is stored (deflating it costs CPU and saves little) */
        $comp = $store ? $body : gzdeflate($body, 9); $m = $store ? 0 : 8;
        $h = pack('vvvVVVVvv', 20, 0x0800, $m, $dt, $crc, strlen($comp), $len, strlen($name), 0);
        $data .= "PK\x03\x04" . $h . $name . $comp;
        $cd .= "PK\x01\x02" . pack('vvvvVVVVvvvvvVV', 20, 20, 0x0800, $m, $dt, $crc, strlen($comp), $len, strlen($name), 0, 0, 0, 0, 0, $off) . $name;
        $n++;
    }
    return $data . $cd . "PK\x05\x06" . pack('vvvvVVv', 0, 0, $n, $n, strlen($cd), strlen($data), 0);
}
