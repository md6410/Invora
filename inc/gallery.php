<?php
/* دفتر فاکتور — کاتالوگ و گالری (عکس، فیلم، فایل)

   هر فایل یک کلید تصادفی خودش را دارد (K) و به تکه‌های ۱ مگابایتی تقسیم و هر تکه جدا با AES-256-GCM رمز می‌شود
   (بدون فشرده‌سازی؛ فیلم و عکس فشرده‌شدنی نیستند). K با کلید داده قفل است، پس فقط کاربرِ واردشده آن را باز می‌کند.
   لینک اشتراک: فایل‌ها دوباره رمز نمی‌شوند؛ فهرست فایل‌ها و K هرکدام داخل «بسته‌ی لینک» می‌رود که مثل فایل فاکتور با
   کلیدِ ساخته‌شده از توکن لینک و رمز آن قفل است. پس همه‌ی قانون‌های لینک فاکتور (رمز، زمان، تعداد، ۵ رمز اشتباه، گزارش)
   برای گالری هم برقرار است.
   تکه‌تکه بودن دو فایده دارد: بارگذاری فیلم‌های بزرگ از سقف post_max_size هاست رد نمی‌شود، و پخش فیلم با
   درخواست‌های Range (جلو و عقب زدن) فقط همان تکه‌های لازم را باز می‌کند. */
declare(strict_types=1);
if (!defined('DF')) { http_response_code(403); exit; }

const GAL_CHUNK = 1048576;                 /* ۱ مگابایت */
const GAL_MAX = 1024 * 1024 * 1024;        /* سقف هر فایل: ۱ گیگابایت */

function gal_items(): array { return df_read('gallery.json', ['items' => []])['items'] ?? []; }
function gal_dir(string $id): string { return df_path('gallery/' . $id); }
function gal_valid_id(string $id): bool { return (bool)preg_match('/^[a-f0-9]{20}$/', $id); }
function gal_cenc(string $plain, string $k, string $aad): string {
    $iv = random_bytes(12); $tag = '';
    $ct = openssl_encrypt($plain, 'aes-256-gcm', $k, OPENSSL_RAW_DATA, $iv, $tag, $aad, 16);
    if ($ct === false) throw new RuntimeException('encrypt failed');
    return 'DFC1' . $iv . $tag . $ct;
}
function gal_cdec(string $blob, string $k, string $aad): ?string {
    if (strlen($blob) < 32 || strncmp($blob, 'DFC1', 4) !== 0) return null;
    $p = openssl_decrypt(substr($blob, 32), 'aes-256-gcm', $k, OPENSSL_RAW_DATA, substr($blob, 4, 12), substr($blob, 16, 16), $aad);
    return $p === false ? null : $p;
}
function gal_key(array $it, string $dek): ?string { return df_dec((string)base64_decode((string)($it['kw'] ?? '')), $dek, 'galk'); }
function gal_meta(array $it, string $dek): array {
    $j = df_dec((string)base64_decode((string)($it['m'] ?? '')), $dek, 'galm');
    $m = $j ? json_decode($j, true) : null;
    return is_array($m) ? $m : [];
}
function gal_set_meta(string $id, array $meta, string $dek): void {
    $blob = base64_encode(df_enc(json_encode($meta, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), $dek, 'galm'));
    df_update('gallery.json', function (array &$d) use ($id, $blob) { if (isset($d['items'][$id])) $d['items'][$id]['m'] = $blob; }, ['items' => []]);
}
function gal_clean_meta(array $in, array $old = []): array {
    $s = fn($k, $n) => mb_substr(trim((string)($in[$k] ?? $old[$k] ?? '')), 0, $n);
    $type = strtolower($s('type', 120));
    if (!preg_match('~^[a-z0-9.+\-]+/[a-z0-9.+\-]+$~', $type)) $type = 'application/octet-stream';
    return ['name' => preg_replace('~[\\\\/:*?"<>|\x00-\x1f]+~u', '-', $s('name', 160)) ?: 'file', 'type' => $type,
        'kind' => in_array(($k = (string)($in['kind'] ?? $old['kind'] ?? '')), ['catalog', 'company', 'official', 'other'], true) ? $k : 'media',
        'origin' => in_array(($o = $s('origin', 20)), ['official', 'company', 'assets', 'hr', 'letters', 'products', 'media', 'catalog', 'other'], true) ? $o : '',
        'exp' => preg_replace('~[^0-9/]~', '', $s('exp', 12)), 'co' => preg_replace('~[^A-Za-z0-9]~', '', $s('co', 20)),
        'title' => $s('title', 160), 'desc' => $s('desc', 2000), 'folder' => $s('folder', 80),
        'fp' => preg_replace('/[^A-Za-z0-9_.:|\-]/', '', $s('fp', 200))]; /* نشانه‌ی فایل روی رایانه‌ی کاربر (نام، اندازه، زمان) برای ادامه‌ی بارگذاری */
}
function gal_have(string $id): array {
    $out = [];
    foreach (glob(gal_dir($id) . '/*.bin') ?: [] as $f) { $b = basename($f, '.bin'); if (ctype_digit($b)) $out[] = (int)$b; }
    sort($out);
    return $out;
}
/* فضای سرور برای گالری: فضای آزاد دیسک منهای ذخیره‌ی همیشگی و منهای باقیِ بارگذاری‌های نیمه‌کاره، و سقف دلخواه */
function gal_space(): array {
    $items = gal_items(); $used = 0; $pending = 0;
    foreach ($items as $id => $it) {
        $used += (int)$it['size'];
        if (empty($it['done'])) $pending += max(0, (int)$it['size'] - count(gal_have((string)$id)) * GAL_CHUNK);
    }
    $free = @disk_free_space(df_data_dir());
    $reserve = max(0, (int)DF_GALLERY_RESERVE_MB) * 1048576;
    $quota = max(0, (int)DF_GALLERY_QUOTA_MB) * 1048576;
    $avail = $free === false ? PHP_INT_MAX : (int)$free - $reserve - $pending;
    if ($quota > 0) $avail = min($avail, $quota - $used);
    return ['free' => $free === false ? -1 : (int)$free, 'used' => $used, 'pending' => $pending, 'reserve' => $reserve, 'quota' => $quota,
        'avail' => max(0, $avail), 'max' => GAL_MAX, 'chunk' => GAL_CHUNK];
}
function gal_cleanup_stale(): void { /* بارگذاری نیمه‌کاره‌ای که ۱۰ روز دست نخورده، پاک می‌شود */
    foreach (gal_items() as $id => $it) {
        if (!empty($it['done'])) continue;
        $last = (int)$it['at'];
        foreach (glob(gal_dir((string)$id) . '/*.bin') ?: [] as $f) $last = max($last, (int)@filemtime($f));
        if ($last < time() - 10 * 86400) gal_delete((string)$id);
    }
}
function gal_public(string $dek): array {
    if (random_int(1, 10) === 1) gal_cleanup_stale();
    $out = [];
    foreach (gal_items() as $id => $it) {
        $m = gal_meta($it, $dek);
        $out[] = ['id' => $id, 'size' => (int)$it['size'], 'done' => !empty($it['done']), 'thumb' => !empty($it['thumb']), 'at' => ((int)$it['at']) * 1000, 'by' => $it['by'] ?? '',
            'chunks' => (int)$it['chunks'], 'have' => empty($it['done']) ? count(gal_have((string)$id)) : (int)$it['chunks']] + $m;
    }
    usort($out, fn($a, $b) => $b['at'] <=> $a['at']);
    return $out;
}
function gal_new(array $meta, int $size, string $dek, string $user): string {
    $id = bin2hex(random_bytes(10)); $k = random_bytes(32);
    $rec = ['kw' => base64_encode(df_enc($k, $dek, 'galk')), 'm' => base64_encode(df_enc(json_encode($meta, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), $dek, 'galm')),
        'size' => $size, 'chunks' => max(1, (int)ceil($size / GAL_CHUNK)), 'at' => time(), 'by' => $user, 'done' => false, 'thumb' => false];
    if (!is_dir(gal_dir($id))) @mkdir(gal_dir($id), 0700, true);
    df_update('gallery.json', function (array &$d) use ($id, $rec) { $d['items'][$id] = $rec; }, ['items' => []]);
    return $id;
}
function gal_put_chunk(string $id, int $i, string $bin, string $dek): ?string {
    $it = gal_items()[$id] ?? null;
    if (!$it) return 'فایل پیدا نشد.';
    if (!empty($it['done'])) return 'بارگذاری این فایل تمام شده است.';
    if ($i < 0 || $i >= (int)$it['chunks']) return 'شماره‌ی تکه نامعتبر است.';
    $free = @disk_free_space(df_data_dir());
    if ($free !== false && $free < 3 * GAL_CHUNK + 20 * 1048576) return 'NOSPACE:فضای سرور پر شد؛ بارگذاری متوقف شد. فضا آزاد کنید و «ادامه» را بزنید.';
    $want = ($i === (int)$it['chunks'] - 1) ? (int)$it['size'] - $i * GAL_CHUNK : GAL_CHUNK;
    if (strlen($bin) !== $want) return 'اندازه‌ی تکه درست نیست.';
    $k = gal_key($it, $dek); if ($k === null) return 'کلید فایل باز نشد.';
    df_write_atomic(gal_dir($id) . '/' . $i . '.bin', gal_cenc($bin, $k, $id . ':' . $i));
    return null;
}
function gal_finish(string $id): ?string {
    $it = gal_items()[$id] ?? null;
    if (!$it) return 'فایل پیدا نشد.';
    for ($i = 0; $i < (int)$it['chunks']; $i++) if (!is_file(gal_dir($id) . '/' . $i . '.bin')) return 'بخشی از فایل نرسیده است؛ دوباره بارگذاری کنید.';
    df_update('gallery.json', function (array &$d) use ($id) { if (isset($d['items'][$id])) $d['items'][$id]['done'] = true; }, ['items' => []]);
    return null;
}
function gal_put_thumb(string $id, string $bin, string $dek): void {
    $it = gal_items()[$id] ?? null; if (!$it) return;
    $k = gal_key($it, $dek); if ($k === null) return;
    df_write_atomic(gal_dir($id) . '/t.bin', gal_cenc($bin, $k, $id . ':t'));
    df_update('gallery.json', function (array &$d) use ($id) { if (isset($d['items'][$id])) $d['items'][$id]['thumb'] = true; }, ['items' => []]);
}
function gal_delete(string $id): void {
    df_update('gallery.json', function (array &$d) use ($id) { unset($d['items'][$id]); }, ['items' => []]);
    foreach (glob(gal_dir($id) . '/*') ?: [] as $f) @unlink($f);
    @rmdir(gal_dir($id));
}
/* «بسته‌ی لینک»: فهرست فایل‌های انتخاب‌شده همراه کلید هرکدام (بعد با کلید لینک رمز می‌شود) */
/* اطلاعات پروفایل محصول که در لینک می‌رود (عنوان، توضیح، جدول مشخصات، قیمت) */
function gal_clean_info($in): ?array {
    if (!is_array($in)) return null;
    $specs = [];
    foreach (array_slice((array)($in['specs'] ?? []), 0, 60) as $r) {
        if (!is_array($r)) continue;
        $k = mb_substr(trim((string)($r[0] ?? '')), 0, 120); $v = mb_substr(trim((string)($r[1] ?? '')), 0, 600);
        if ($k !== '' || $v !== '') $specs[] = [$k, $v];
    }
    $o = ['name' => mb_substr(trim((string)($in['name'] ?? '')), 0, 160), 'about' => mb_substr(trim((string)($in['about'] ?? '')), 0, 6000), 'specs' => $specs,
        'price' => mb_substr(trim((string)($in['price'] ?? '')), 0, 80), 'img' => ''];
    $img = (string)($in['img'] ?? '');
    if (preg_match('~^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$~', $img) && strlen($img) < 400000) $o['img'] = $img;
    return ($o['name'] !== '' || $o['about'] !== '' || $specs) ? $o : null;
}
function gal_pack(array $ids, string $title, string $dek, ?array $info = null): ?array {
    $all = gal_items(); $items = [];
    foreach ($ids as $id) {
        $id = (string)$id; $it = $all[$id] ?? null;
        if (!$it || empty($it['done'])) continue;
        $k = gal_key($it, $dek); if ($k === null) continue;
        $m = gal_meta($it, $dek);
        $items[] = ['id' => $id, 'name' => $m['name'] ?? 'file', 'type' => $m['type'] ?? 'application/octet-stream', 'kind' => $m['kind'] ?? 'media',
            'title' => $m['title'] ?? '', 'desc' => $m['desc'] ?? '', 'size' => (int)$it['size'], 'thumb' => !empty($it['thumb']), 'k' => base64_encode($k)];
    }
    return ($items || $info) ? ['v' => 1, 'title' => $title, 'items' => $items] + ($info ? ['info' => $info] : []) : null;
}
function gal_inline_type(string $type): bool {
    return (bool)preg_match('~^(image/(jpeg|png|gif|webp|avif|bmp)|video/(mp4|webm|ogg|quicktime|x-m4v)|audio/(mpeg|mp4|ogg|wav|webm|x-m4a)|application/pdf)$~', $type);
}
/* پخش/دانلود یک فایل با پشتیبانی Range (برای جلو و عقب زدن فیلم) */
function gal_stream(string $id, string $k, string $type, string $name, bool $dl, bool $thumb = false): void {
    $it = gal_items()[$id] ?? null;
    if (!$it || (!$thumb && empty($it['done']))) { http_response_code(404); exit; }
    while (ob_get_level()) ob_end_clean();
    if ($thumb) {
        $p = is_file(gal_dir($id) . '/t.bin') ? gal_cdec((string)file_get_contents(gal_dir($id) . '/t.bin'), $k, $id . ':t') : null;
        if ($p === null) { http_response_code(404); exit; }
        header('Content-Type: image/jpeg'); header('Content-Length: ' . strlen($p)); header('Cache-Control: private, max-age=600');
        echo $p; exit;
    }
    $size = (int)$it['size']; $start = 0; $end = $size - 1; $code = 200;
    if (!empty($_SERVER['HTTP_RANGE']) && preg_match('/^bytes=(\d*)-(\d*)$/', trim((string)$_SERVER['HTTP_RANGE']), $m) && ($m[1] !== '' || $m[2] !== '')) {
        if ($m[1] === '') { $start = max(0, $size - (int)$m[2]); }
        else { $start = (int)$m[1]; if ($m[2] !== '') $end = min($end, (int)$m[2]); }
        if ($start > $end || $start >= $size) { http_response_code(416); header("Content-Range: bytes */$size"); exit; }
        $code = 206;
    }
    $inline = !$dl && gal_inline_type($type);
    @set_time_limit(0);
    http_response_code($code);
    header('Content-Type: ' . ($inline ? $type : 'application/octet-stream'));
    header('Accept-Ranges: bytes');
    header('Content-Length: ' . ($end - $start + 1));
    if ($code === 206) header("Content-Range: bytes $start-$end/$size");
    header('Content-Disposition: ' . ($inline ? 'inline' : 'attachment') . "; filename=\"file\"; filename*=UTF-8''" . rawurlencode($name));
    header('X-Content-Type-Options: nosniff');
    if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'HEAD') exit;
    for ($i = intdiv($start, GAL_CHUNK); $i <= intdiv($end, GAL_CHUNK); $i++) {
        $p = gal_cdec((string)@file_get_contents(gal_dir($id) . '/' . $i . '.bin'), $k, $id . ':' . $i);
        if ($p === null) break;
        $cs = $i * GAL_CHUNK; $a = max($start, $cs) - $cs; $b = min($end, $cs + strlen($p) - 1) - $cs;
        echo substr($p, $a, $b - $a + 1);
        flush();
        if (connection_aborted()) break;
    }
    exit;
}
function gal_fmt_size(int $n): string { return $n >= 1048576 ? df_fa_num(number_format($n / 1048576, 1)) . ' مگابایت' : df_fa_num((string)max(1, (int)round($n / 1024))) . ' کیلوبایت'; }
