<?php
/* دفتر فاکتور — نمایش یا دانلود فایل‌های کاتالوگ و گالری برای کاربرِ واردشده (با Range برای فیلم) */
declare(strict_types=1);
define('DF', 1);
require __DIR__ . '/inc/lib.php';

df_headers('api');
df_session_start();
if (!df_logged_in()) { http_response_code(401); header('Content-Type: text/plain; charset=utf-8'); exit('ابتدا وارد برنامه شوید.'); }
$dek = df_dek();
session_write_close();
$id = (string)($_GET['id'] ?? '');
if (!gal_valid_id($id)) { http_response_code(404); exit; }
$it = gal_items()[$id] ?? null;
$k = $it ? gal_key($it, (string)$dek) : null;
if (!$it || $k === null) { http_response_code(404); exit; }
$m = gal_meta($it, (string)$dek);
gal_stream($id, $k, (string)($m['type'] ?? ''), (string)($m['name'] ?? 'file'), isset($_GET['dl']), isset($_GET['thumb']));
