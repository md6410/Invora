<?php
/* دفتر فاکتور — به‌روزرسانی خودکار از گیت‌هاب
   برنامه هر چند دقیقه (وقتی کسی وارد شده) آخرین commit شاخه‌ی اصلی مخزن را بررسی می‌کند.
   اگر تازه بود: فایل ZIP همان commit را می‌گیرد، نحو همه‌ی فایل‌های PHP را بررسی می‌کند، از فایل‌های فعلی نسخه‌ی پشتیبان
   می‌سازد، فایل‌های فهرست‌شده در deploy-files.txt را جایگزین می‌کند و در پایان سلامت سایت را می‌سنجد؛
   اگر سایت بالا نیامد، نسخه‌ی قبلی را برمی‌گرداند. پوشه‌ی داده و inc/config.local.php هیچ‌وقت دست نمی‌خورند. */
declare(strict_types=1);
if (!defined('DF')) { http_response_code(403); exit; }

defined('DF_UPDATE_REPO') || define('DF_UPDATE_REPO', 'md6410/Invora');
defined('DF_UPDATE_BRANCH') || define('DF_UPDATE_BRANCH', 'main');
/* GitHub endpoints (overridable in inc/config.local.php, e.g. for a mirror) */
defined('DF_GH_API') || define('DF_GH_API', 'https://api.github.com');
defined('DF_GH_WEB') || define('DF_GH_WEB', 'https://github.com');
defined('DF_GH_RAW') || define('DF_GH_RAW', 'https://raw.githubusercontent.com');
defined('DF_GH_ZIP') || define('DF_GH_ZIP', 'https://codeload.github.com');

function df_app_root(): string { return dirname(__DIR__); }
function df_app_version(?string $html = null): string {
    if ($html === null) $html = (string)@file_get_contents(df_app_root() . '/app.html', false, null, 0, 8192);
    return preg_match('/<meta name="app-version" content="([0-9][0-9A-Za-z.\-]*)"/', $html, $m) ? $m[1] : '';
}
function df_release(): array { $j = json_decode((string)@file_get_contents(__DIR__ . '/release.json'), true); return is_array($j) ? $j : []; }
function df_upd_state(): array { return array_merge(['auto' => true, 'every' => 10], df_read('update.json', [])); }

/* HTTP GET returning [status, body]; status 0 = network error */
function df_http(string $url, int $timeout = 20, array $headers = []): array {
    if (!function_exists('curl_init')) {
        $ctx = stream_context_create(['http' => ['timeout' => $timeout, 'ignore_errors' => true, 'header' => "User-Agent: Invora-Updater\r\n" . implode("\r\n", $headers)]]);
        $b = @file_get_contents($url, false, $ctx);
        $code = 0;
        foreach ($http_response_header ?? [] as $h) if (preg_match('~^HTTP/\S+\s+(\d{3})~', $h, $m)) $code = (int)$m[1];
        return [$b === false ? 0 : $code, (string)$b];
    }
    $c = curl_init($url);
    curl_setopt_array($c, [CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 5,
        CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => 8, CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_USERAGENT => 'Invora-Updater', CURLOPT_HTTPHEADER => $headers]);
    if (defined('CURLOPT_PROTOCOLS')) curl_setopt($c, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    $b = curl_exec($c);
    $code = $b === false ? 0 : (int)curl_getinfo($c, CURLINFO_HTTP_CODE);
    curl_close($c);
    return [$code, $b === false ? '' : (string)$b];
}

/* latest commit of the branch: GitHub API, falling back to the git smart-HTTP ref list */
function df_upd_latest(): ?array {
    [$c, $b] = df_http(DF_GH_API . '/repos/' . DF_UPDATE_REPO . '/commits/' . rawurlencode(DF_UPDATE_BRANCH), 15, ['Accept: application/vnd.github+json']);
    $j = $c === 200 ? json_decode($b, true) : null;
    if (is_array($j) && preg_match('/^[0-9a-f]{40}$/', (string)($j['sha'] ?? ''))) {
        return ['sha' => $j['sha'], 'date' => (string)($j['commit']['committer']['date'] ?? ''), 'msg' => trim(strtok((string)($j['commit']['message'] ?? ''), "\n"))];
    }
    [$c, $b] = df_http(DF_GH_WEB . '/' . DF_UPDATE_REPO . '.git/info/refs?service=git-upload-pack', 15);
    if ($c === 200 && preg_match('~([0-9a-f]{40}) refs/heads/' . preg_quote(DF_UPDATE_BRANCH, '~') . '\b~', $b, $m)) return ['sha' => $m[1], 'date' => '', 'msg' => ''];
    return null;
}
function df_upd_remote_version(string $sha): string {
    [$c, $b] = df_http(DF_GH_RAW . '/' . DF_UPDATE_REPO . '/' . $sha . '/app.html', 15, ['Range: bytes=0-8191']);
    return ($c === 200 || $c === 206) ? df_app_version($b) : '';
}

function df_upd_safe_rel(string $p): bool {
    return (bool)preg_match('~^(\.?[A-Za-z0-9_\-][A-Za-z0-9_.\-]*)(/\.?[A-Za-z0-9_\-][A-Za-z0-9_.\-]*)?$~', $p)
        && strpos($p, '..') === false && $p !== 'inc/config.local.php' && substr($p, -4) !== '.ini';
}
/* keep blocks that cPanel / LiteSpeed generated in .htaccess (e.g. the PHP version handler) */
function df_upd_merge_htaccess(string $new, string $old): string {
    $keep = [];
    $in = false;
    foreach (preg_split('/\r\n|\n|\r/', $old) as $line) {
        if (preg_match('/^#\s*(php -- )?BEGIN /', $line)) $in = true;
        if ($in) $keep[] = $line;
        if (preg_match('/^#\s*(php -- )?END /', $line)) $in = false;
    }
    return rtrim($new) . "\n" . ($keep ? "\n" . implode("\n", $keep) . "\n" : '');
}
function df_upd_opcache(array $files): void {
    if (function_exists('opcache_invalidate')) foreach ($files as $f) @opcache_invalidate($f, true);
}
function df_upd_write(string $abs, string $content): void {
    $dir = dirname($abs);
    if (!is_dir($dir)) @mkdir($dir, 0755, true);
    $tmp = $abs . '.upd' . bin2hex(random_bytes(3));
    if (@file_put_contents($tmp, $content, LOCK_EX) === false) throw new RuntimeException('نوشتن فایل ممکن نشد: ' . basename($abs));
    @chmod($tmp, 0644);
    if (!@rename($tmp, $abs)) { @unlink($tmp); throw new RuntimeException('جایگزینی فایل ممکن نشد: ' . basename($abs)); }
}
function df_upd_health(): array {
    $base = df_base_url();
    [$c, $b] = df_http($base . 'index.php?df_health=1&r=' . bin2hex(random_bytes(4)), 15);
    if ($c === 0) return ['ok' => null, 'note' => 'سنجش سلامت انجام نشد (سرور به خودش دسترسی نداشت).'];
    if ($c !== 200 || strncmp($b, 'ok', 2) !== 0) return ['ok' => false, 'note' => 'index.php: HTTP ' . $c];
    /* api.php must answer GET with a JSON "method" error, d.php without a token with a normal page */
    [$c, $b] = df_http($base . 'api.php', 15);
    if ($c !== 0 && ($c >= 500 || strpos($b, '"method"') === false)) return ['ok' => false, 'note' => 'api.php: HTTP ' . $c];
    [$c] = df_http($base . 'd.php', 15);
    if ($c >= 500) return ['ok' => false, 'note' => 'd.php: HTTP ' . $c];
    return ['ok' => true, 'note' => 'HTTP 200'];
}

/* download, validate and install commit $sha */
function df_upd_apply(array $latest, string $by): array {
    $lp = df_path('locks');
    if (!is_dir($lp)) @mkdir($lp, 0700, true);
    $lock = fopen($lp . '/update.lock', 'c');
    if (!flock($lock, LOCK_EX | LOCK_NB)) return ['ok' => false, 'error' => 'به‌روزرسانی دیگری در حال انجام است.'];
    try {
        $sha = $latest['sha'];
        [$c, $zipData] = df_http(DF_GH_ZIP . '/' . DF_UPDATE_REPO . '/zip/' . $sha, 60);
        if ($c !== 200 || strncmp($zipData, "PK", 2) !== 0) [$c, $zipData] = df_http(DF_GH_API . '/repos/' . DF_UPDATE_REPO . '/zipball/' . $sha, 60);
        if ($c !== 200 || strncmp($zipData, "PK", 2) !== 0) throw new RuntimeException('دریافت فایل نسخه‌ی تازه از گیت‌هاب ممکن نشد.');
        if (!class_exists('ZipArchive')) throw new RuntimeException('افزونه‌ی zip در PHP فعال نیست (Select PHP Version ← zip).');
        $zf = df_path('tmp-update.zip');
        df_write_atomic($zf, $zipData);
        $zip = new ZipArchive();
        if ($zip->open($zf) !== true) throw new RuntimeException('فایل ZIP نسخه‌ی تازه خراب است.');
        $first = (string)$zip->getNameIndex(0);
        $prefix = strpos($first, '/') !== false ? substr($first, 0, strpos($first, '/') + 1) : '';
        $manifest = $zip->getFromName($prefix . 'deploy-files.txt');
        if ($manifest === false) throw new RuntimeException('فهرست فایل‌ها (deploy-files.txt) در نسخه‌ی تازه نیست.');
        $files = [];
        foreach (preg_split('/\r\n|\n|\r/', $manifest) as $line) {
            $p = trim($line);
            if ($p === '' || $p[0] === '#') continue;
            if (!df_upd_safe_rel($p)) throw new RuntimeException('مسیر نامعتبر در فهرست: ' . $p);
            $content = $zip->getFromName($prefix . $p);
            if ($content === false || $content === '') throw new RuntimeException('فایل ' . $p . ' در نسخه‌ی تازه نیست.');
            $files[$p] = $content;
        }
        $zip->close(); @unlink($zf);
        foreach (['app.html', 'index.php', 'api.php', 'd.php', 'inc/lib.php', 'inc/update.php', 'inc/crypto.php', 'inc/config.php'] as $need)
            if (!isset($files[$need])) throw new RuntimeException('فایل ضروری ' . $need . ' در نسخه‌ی تازه نیست.');
        $ver = df_app_version($files['app.html']);
        if ($ver === '') throw new RuntimeException('شماره‌ی نسخه در app.html تازه پیدا نشد.');
        foreach ($files as $p => $content) {
            if (substr($p, -4) !== '.php') continue;
            try { token_get_all($content, TOKEN_PARSE); }
            catch (Throwable $e) { throw new RuntimeException('خطای نحوی در ' . $p . ' (خط ' . $e->getLine() . '): نصب نشد.'); }
        }
        /* back up the current files */
        $root = df_app_root();
        $bk = df_path('releases/previous');
        if (is_dir($bk)) foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($bk, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $f) $f->isDir() ? @rmdir((string)$f) : @unlink((string)$f);
        $current = array_unique(array_merge(array_keys($files), ['inc/release.json']));
        $backed = [];
        foreach ($current as $p) if (is_file($root . '/' . $p)) { $dst = $bk . '/' . $p; if (!is_dir(dirname($dst))) @mkdir(dirname($dst), 0700, true); if (@copy($root . '/' . $p, $dst)) $backed[] = $p; }
        $oldRel = df_release();
        /* install */
        $written = [];
        try {
            foreach ($files as $p => $content) {
                $abs = $root . '/' . $p;
                if ($p === '.htaccess') $content = df_upd_merge_htaccess($content, is_file($abs) ? (string)file_get_contents($abs) : '');
                df_upd_write($abs, $content);
                $written[] = $abs;
            }
            df_upd_write(__DIR__ . '/release.json', json_encode(['sha' => $sha, 'version' => $ver, 'at' => time(), 'by' => $by, 'msg' => $latest['msg'] ?? ''], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));
        } catch (Throwable $e) {
            df_upd_restore($backed, $bk, $root, array_keys($files));
            throw $e;
        }
        df_upd_opcache($written);
        $h = df_upd_health();
        if ($h['ok'] === false) {
            df_upd_restore($backed, $bk, $root, array_keys($files));
            throw new RuntimeException('سایت بعد از نصب نسخه‌ی ' . $ver . ' بالا نیامد (' . $h['note'] . ')؛ نسخه‌ی قبلی برگردانده شد.');
        }
        return ['ok' => true, 'version' => $ver, 'sha' => $sha, 'from' => $oldRel['version'] ?? '', 'note' => $h['note']];
    } finally { flock($lock, LOCK_UN); fclose($lock); }
}
function df_upd_restore(array $backed, string $bk, string $root, array $newFiles): void {
    $touched = [];
    foreach ($backed as $p) { if (@copy($bk . '/' . $p, $root . '/' . $p)) $touched[] = $root . '/' . $p; }
    foreach ($newFiles as $p) if (!in_array($p, $backed, true) && is_file($root . '/' . $p)) @unlink($root . '/' . $p); /* files that did not exist before */
    df_upd_opcache($touched);
}

/* check (respecting the interval unless $force) and, if $install, install a newer commit */
function df_upd_run(bool $force, bool $install, string $by): array {
    $st = df_upd_state();
    $rel = df_release();
    $out = ['checked' => false, 'updated' => false];
    if (!$force && time() - (int)($st['lastCheck'] ?? 0) < max(2, (int)$st['every']) * 60) return $out;
    df_update('update.json', function (array &$s) { $s['lastCheck'] = time(); }, []);
    $latest = df_upd_latest();
    $out['checked'] = true;
    if (!$latest) {
        df_update('update.json', function (array &$s) { $s['lastError'] = 'گیت‌هاب در دسترس نبود.'; $s['lastErrorAt'] = time(); }, []);
        $out['error'] = 'اتصال به گیت‌هاب برقرار نشد.';
        return $out;
    }
    $isNew = ($rel['sha'] ?? '') !== $latest['sha'];
    $remoteVer = $isNew ? (($st['latestSha'] ?? '') === $latest['sha'] && !empty($st['latestVersion']) ? $st['latestVersion'] : df_upd_remote_version($latest['sha'])) : ($rel['version'] ?? df_app_version());
    df_update('update.json', function (array &$s) use ($latest, $remoteVer) { $s['latestSha'] = $latest['sha']; $s['latestVersion'] = $remoteVer; $s['latestMsg'] = $latest['msg']; $s['latestDate'] = $latest['date']; }, []);
    if (!$isNew) df_update('update.json', function (array &$s) { unset($s['lastError'], $s['failedSha']); }, []);
    if (!$isNew || !$install) return $out + ['available' => $isNew];
    /* a commit that already failed to install is retried only on request (not every few minutes) */
    if (!$force && ($st['failedSha'] ?? '') === $latest['sha']) return $out + ['available' => true, 'error' => (string)($st['lastError'] ?? '')];
    try {
        $r = df_upd_apply($latest, $by);
    } catch (Throwable $e) {
        $r = ['ok' => false, 'error' => $e->getMessage()];
    }
    if (empty($r['version'])) $r['version'] = $remoteVer;
    df_update('update.json', function (array &$s) use ($r, $by) {
        $s['history'] = array_slice(array_merge([['at' => time(), 'by' => $by, 'ok' => $r['ok'], 'version' => $r['version'] ?? '', 'from' => $r['from'] ?? '', 'error' => $r['error'] ?? '']], $s['history'] ?? []), 0, 20);
        if ($r['ok']) { unset($s['lastError'], $s['failedSha']); } else { $s['lastError'] = $r['error']; $s['lastErrorAt'] = time(); $s['failedSha'] = $s['latestSha'] ?? ''; }
    }, []);
    return array_merge($out, ['updated' => $r['ok'], 'version' => $r['version'] ?? '', 'error' => $r['error'] ?? '']);
}
function df_upd_status(): array {
    $st = df_upd_state(); $rel = df_release();
    return ['installed' => ['version' => df_app_version(), 'sha' => $rel['sha'] ?? '', 'at' => ($rel['at'] ?? 0) * 1000, 'by' => $rel['by'] ?? ''],
        'latest' => ['sha' => $st['latestSha'] ?? '', 'version' => $st['latestVersion'] ?? '', 'msg' => $st['latestMsg'] ?? '', 'date' => $st['latestDate'] ?? ''],
        'auto' => (bool)$st['auto'], 'every' => (int)$st['every'], 'lastCheck' => ($st['lastCheck'] ?? 0) * 1000,
        'lastError' => $st['lastError'] ?? '', 'lastErrorAt' => ($st['lastErrorAt'] ?? 0) * 1000, 'history' => array_map(fn($h) => ['at' => $h['at'] * 1000] + $h, $st['history'] ?? []),
        'repo' => DF_UPDATE_REPO, 'zip' => class_exists('ZipArchive')];
}
