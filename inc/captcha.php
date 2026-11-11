<?php
/* دفتر فاکتور — کپچا (بی سرویس بیرونی) برای جلوی ربات در «فرستادن کد ورود پیامکی»

   از درخواستِ چهارم در یک ساعت (از همین مرورگر یا همین اینترنت) فرستادن کد بی کپچا انجام نمی‌شود
   تا کسی نتواند با ربات پیامک پشت پیامک بفرستد و اعتبار پنل را خالی کند.
   تصویر PNG با GD: پنج رقم با جابه‌جایی و چرخش و خط و نقطه؛ پاسخ فقط در نشست است (هش‌شده)،
   یک‌بارمصرف و ۵ دقیقه معتبر. اگر GD روی هاست نباشد، یک جمع ساده‌ی دو عدد با تصویر SVG ِ خط‌خطی. */
declare(strict_types=1);
if (!defined('DF')) { http_response_code(403); exit; }

const DF_CAP_FREE = 3;          /* چند بار فرستادنِ کد در یک ساعت بی کپچا */

/** کپچا لازم است؟ (شمارش از نشست و از آی‌پی، هر کدام بیشتر) */
function df_cap_needed(): bool
{
    $ip = df_ip();
    $n = count(array_filter((array)(df_read('otp-ip.json', [])[$ip] ?? []), fn($t) => $t > time() - 3600));
    $s = count(array_filter((array)($_SESSION['otp_sends'] ?? []), fn($t) => $t > time() - 3600));
    return max($n, $s) >= DF_CAP_FREE;
}
/** یک درخواستِ فرستادنِ کد را می‌شمارد */
function df_cap_count(): void
{
    $_SESSION['otp_sends'] = array_values(array_filter(array_merge((array)($_SESSION['otp_sends'] ?? []), [time()]), fn($t) => $t > time() - 3600));
    $ip = df_ip();
    df_update('otp-ip.json', function (array &$a) use ($ip) {
        foreach ($a as $k => $v) { $a[$k] = array_values(array_filter((array)$v, fn($t) => $t > time() - 3600)); if (!$a[$k]) unset($a[$k]); }
        $a[$ip][] = time();
    });
}
function df_cap_check(string $in): bool
{
    $c = $_SESSION['cap'] ?? null;
    unset($_SESSION['cap']);                                  /* یک‌بارمصرف */
    if (!is_array($c) || (int)$c['t'] < time() - 300) return false;
    return password_verify(df_pin_norm($in), (string)$c['h']);
}

/** تصویرِ کپچای تازه را می‌فرستد */
function df_cap_image(): void
{
    header('Cache-Control: no-store');
    if (function_exists('imagecreatetruecolor') && function_exists('imagepng')) {
        $code = '';
        for ($i = 0; $i < 5; $i++) $code .= (string)random_int(1, 9);
        $_SESSION['cap'] = ['h' => password_hash($code, PASSWORD_DEFAULT), 't' => time()];
        $W = 200; $H = 64;
        $im = imagecreatetruecolor($W, $H);
        imagefill($im, 0, 0, imagecolorallocate($im, 246, 247, 245));
        for ($i = 0; $i < 6; $i++) {
            $c = imagecolorallocate($im, random_int(150, 210), random_int(150, 210), random_int(150, 210));
            imagesetthickness($im, random_int(1, 2));
            imageline($im, random_int(0, $W), random_int(0, $H), random_int(0, $W), random_int(0, $H), $c);
        }
        for ($i = 0; $i < strlen($code); $i++) {
            $g = imagecreatetruecolor(10, 16);
            $bg = imagecolorallocate($g, 246, 247, 245); imagefill($g, 0, 0, $bg); imagecolortransparent($g, $bg);
            imagestring($g, 5, 1, 0, $code[$i], imagecolorallocate($g, random_int(10, 60), random_int(50, 90), random_int(70, 100)));
            $s = random_int(30, 38) / 10;                     /* بزرگ‌نمایی */
            $big = imagecreatetruecolor((int)(10 * $s), (int)(16 * $s));
            $bg2 = imagecolorallocate($big, 246, 247, 245); imagefill($big, 0, 0, $bg2);
            imagecopyresized($big, $g, 0, 0, 0, 0, (int)(10 * $s), (int)(16 * $s), 10, 16);
            $rot = imagerotate($big, random_int(-22, 22), $bg2);
            imagecolortransparent($rot, imagecolorat($rot, 0, 0));
            imagecopymerge($im, $rot, 12 + $i * 36 + random_int(-3, 3), random_int(0, max(0, $H - imagesy($rot))), 0, 0, imagesx($rot), imagesy($rot), 100);
            imagedestroy($g); imagedestroy($big); imagedestroy($rot);
        }
        for ($i = 0; $i < 3; $i++) {
            imagesetthickness($im, 2);
            imageline($im, 0, random_int(8, $H - 8), $W, random_int(8, $H - 8), imagecolorallocate($im, random_int(60, 120), random_int(80, 130), random_int(90, 140)));
        }
        for ($i = 0; $i < 260; $i++) imagesetpixel($im, random_int(0, $W - 1), random_int(0, $H - 1), imagecolorallocate($im, random_int(80, 200), random_int(80, 200), random_int(80, 200)));
        header('Content-Type: image/png');
        imagepng($im); imagedestroy($im);
        return;
    }
    /* بی GD: جمعِ دو عدد، نوشته با خط‌های SVG (نه متن) */
    $a = random_int(2, 9); $b = random_int(2, 9);
    $_SESSION['cap'] = ['h' => password_hash((string)($a + $b), PASSWORD_DEFAULT), 't' => time()];
    $seg = ['0' => 'abcdef', '1' => 'bc', '2' => 'abged', '3' => 'abgcd', '4' => 'fgbc', '5' => 'afgcd', '6' => 'afgedc', '7' => 'abc', '8' => 'abcdefg', '9' => 'abcdfg', '+' => 'pq', '=' => 'rs'];
    $L = ['a' => [0, 0, 1, 0], 'b' => [1, 0, 1, 1], 'c' => [1, 1, 1, 2], 'd' => [0, 2, 1, 2], 'e' => [0, 1, 0, 2], 'f' => [0, 0, 0, 1], 'g' => [0, 1, 1, 1],
          'p' => [0, 1, 1, 1], 'q' => [.5, .5, .5, 1.5], 'r' => [0, .8, 1, .8], 's' => [0, 1.2, 1, 1.2]];
    $p = ''; $x = 12;
    foreach ([(string)$a, '+', (string)$b, '='] as $ch) {
        $dx = random_int(-2, 2); $dy = random_int(-3, 3);
        foreach (str_split($seg[$ch]) as $k) { [$x1, $y1, $x2, $y2] = $L[$k]; $p .= sprintf('M%d %dL%d %d', $x + $x1 * 18 + $dx, 12 + $y1 * 18 + $dy, $x + $x2 * 18 + $dx, 12 + $y2 * 18 + $dy); }
        $x += 40;
    }
    header('Content-Type: image/svg+xml');
    echo '<svg xmlns="http://www.w3.org/2000/svg" width="200" height="64" viewBox="0 0 200 64"><rect width="200" height="64" fill="#f6f7f5"/>'
        . '<path d="M0 ' . random_int(10, 54) . 'L200 ' . random_int(10, 54) . '" stroke="#9bb" stroke-width="2"/>'
        . '<path d="' . $p . '" stroke="#1e3d3a" stroke-width="4" stroke-linecap="round" fill="none"/></svg>';
}
