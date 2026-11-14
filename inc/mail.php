<?php
/* دفتر فاکتور — ایمیل (SMTP)، برای فرستادن نامه‌ها

   تنظیمات صندوق (سرور، پورت، کاربر، رمز) در data/mail.cfg رمزشده با کلید داده نوشته می‌شود
   (df_swrite) و فقط بعد از ورود خوانده می‌شود؛ رمز صندوق هیچ‌وقت به مرورگر برنمی‌گردد.
   فرستادن: اتصال مستقیم SMTP (ssl یا starttls یا بدون رمزنگاری)، متن فارسی با base64، پیوست اختیاری. */
declare(strict_types=1);
if (!defined('DF')) { http_response_code(403); exit; }

function mail_cfg(string $dek): array {
    $raw = df_sread('mail.cfg', $dek, 'mail');
    $c = $raw ? json_decode($raw, true) : null;
    return array_merge(['host' => '', 'port' => 465, 'sec' => 'ssl', 'user' => '', 'pass' => '', 'from' => '', 'name' => '', 'reply' => ''], is_array($c) ? $c : []);
}
function mail_cfg_save(array $c, string $dek): void { df_swrite('mail.cfg', json_encode($c, JSON_UNESCAPED_UNICODE), $dek, 'mail'); }
function mail_valid(string $e): string { $e = trim($e); return filter_var($e, FILTER_VALIDATE_EMAIL) ? $e : ''; }
function mail_enc_word(string $s): string {
    if ($s === '' || preg_match('/^[\x20-\x7E]*$/', $s)) return $s;
    return '=?UTF-8?B?' . base64_encode($s) . '?=';
}
/** «a@b.c, نام <d@e.f>» → [['name'=>..,'email'=>..],..] */
function mail_parse_addrs(string $s): array {
    $out = [];
    foreach (preg_split('/[,;\n]+/', $s) ?: [] as $p) {
        $p = trim($p); if ($p === '') continue;
        $n = '';
        if (preg_match('/^(.*)<\s*([^>]+)\s*>$/u', $p, $m)) { $n = trim($m[1], " \"'"); $p = trim($m[2]); }
        if ($e = mail_valid($p)) $out[strtolower($e)] = ['name' => $n, 'email' => $e];
    }
    return array_values($out);
}
function mail_addr_header(array $l): string {
    return implode(', ', array_map(fn($a) => ($a['name'] !== '' ? mail_enc_word($a['name']) . ' ' : '') . '<' . $a['email'] . '>', $l));
}
function mail_html_text(string $h): string {
    $h = preg_replace('~<(br|/p|/div|/tr|/h\d)[^>]*>~i', "\n", $h);
    $h = preg_replace('~<(style|script)[^>]*>.*?</\1>~is', '', $h);
    return trim(html_entity_decode(strip_tags((string)$h), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
}
function mail_build(array $c, array $to, array $cc, string $subject, string $html, array $attach): string {
    $eol = "\r\n"; $b1 = 'b1_' . bin2hex(random_bytes(10)); $b2 = 'b2_' . bin2hex(random_bytes(10));
    $host = preg_replace('/^.*@/', '', $c['from']) ?: 'localhost';
    $h = ['MIME-Version: 1.0', 'Date: ' . date('r'), 'Message-ID: <' . bin2hex(random_bytes(10)) . '@' . $host . '>',
        'From: ' . ($c['name'] !== '' ? mail_enc_word($c['name']) . ' ' : '') . '<' . $c['from'] . '>', 'To: ' . mail_addr_header($to)];
    if ($cc) $h[] = 'Cc: ' . mail_addr_header($cc);
    if ($c['reply'] !== '') $h[] = 'Reply-To: ' . $c['reply'];
    $h[] = 'Subject: ' . mail_enc_word($subject);
    $h[] = 'Content-Type: multipart/mixed; boundary="' . $b1 . '"';
    $o = implode($eol, $h) . $eol . $eol . '--' . $b1 . $eol . 'Content-Type: multipart/alternative; boundary="' . $b2 . '"' . $eol . $eol;
    $o .= '--' . $b2 . $eol . 'Content-Type: text/plain; charset=UTF-8' . $eol . 'Content-Transfer-Encoding: base64' . $eol . $eol . chunk_split(base64_encode(mail_html_text($html)), 76, $eol) . $eol;
    $o .= '--' . $b2 . $eol . 'Content-Type: text/html; charset=UTF-8' . $eol . 'Content-Transfer-Encoding: base64' . $eol . $eol . chunk_split(base64_encode($html), 76, $eol) . $eol . '--' . $b2 . '--' . $eol . $eol;
    foreach ($attach as $a) {
        $n = mail_enc_word((string)$a['name']);
        $o .= '--' . $b1 . $eol . 'Content-Type: ' . $a['mime'] . '; name="' . $n . '"' . $eol . 'Content-Transfer-Encoding: base64' . $eol
            . 'Content-Disposition: attachment; filename="' . $n . '"' . $eol . $eol . chunk_split(base64_encode($a['data']), 76, $eol) . $eol;
    }
    return $o . '--' . $b1 . '--' . $eol;
}
/** @return array{ok:bool,msg:string} */
function mail_smtp(array $c, array $rcpts, string $data): array {
    $host = trim((string)$c['host']); $port = (int)$c['port']; $sec = (string)$c['sec'];
    if ($host === '' || $c['from'] === '' || !$rcpts) return ['ok' => false, 'msg' => 'تنظیمات ایمیل کامل نیست.'];
    $fp = @stream_socket_client(($sec === 'ssl' ? 'ssl://' : '') . $host . ':' . $port, $en, $es, 20, STREAM_CLIENT_CONNECT, stream_context_create(['ssl' => ['SNI_enabled' => true, 'peer_name' => $host]]));
    if (!$fp) return ['ok' => false, 'msg' => 'اتصال به سرور ایمیل ممکن نشد: ' . ($es ?: 'بی‌پاسخ')];
    stream_set_timeout($fp, 25);
    $rd = function () use ($fp): array { $o = ''; while (($l = fgets($fp, 8192)) !== false) { $o .= $l; if (strlen($l) < 4 || $l[3] !== '-') break; } return [(int)substr($o, 0, 3), $o]; };
    $say = fn(string $s) => fwrite($fp, $s . "\r\n");
    $bye = function (string $m) use ($fp): array { @fwrite($fp, "QUIT\r\n"); @fclose($fp); return ['ok' => false, 'msg' => $m]; };
    [$code] = $rd(); if ($code !== 220) return $bye('سرور ایمیل پاسخ درست نداد.');
    $me = preg_replace('/^.*@/', '', $c['from']) ?: 'localhost';
    $say('EHLO ' . $me); [$code, $caps] = $rd(); if ($code !== 250) return $bye('سرور EHLO را نپذیرفت.');
    if ($sec === 'tls') {
        $say('STARTTLS'); [$code] = $rd();
        if ($code !== 220 || !@stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) return $bye('برقراری TLS ناموفق بود.');
        $say('EHLO ' . $me); [$code, $caps] = $rd(); if ($code !== 250) return $bye('سرور بعد از TLS پاسخ نداد.');
    }
    if ($c['user'] !== '') {
        if (stripos($caps, 'PLAIN') !== false) { $say('AUTH PLAIN ' . base64_encode("\0" . $c['user'] . "\0" . $c['pass'])); [$code] = $rd(); }
        else {
            $say('AUTH LOGIN'); [$code] = $rd();
            if ($code === 334) { $say(base64_encode($c['user'])); [$code] = $rd(); }
            if ($code === 334) { $say(base64_encode($c['pass'])); [$code] = $rd(); }
        }
        if ($code !== 235) return $bye('نام کاربری یا رمز صندوق پذیرفته نشد.');
    }
    $say('MAIL FROM:<' . $c['from'] . '>'); [$code] = $rd(); if ($code !== 250) return $bye('فرستنده پذیرفته نشد.');
    $ok = 0; $err = '';
    foreach ($rcpts as $r) { $say('RCPT TO:<' . $r . '>'); [$code, $resp] = $rd(); if ($code === 250 || $code === 251) $ok++; else $err = trim($resp); }
    if (!$ok) return $bye('هیچ گیرنده‌ای پذیرفته نشد. ' . $err);
    $say('DATA'); [$code] = $rd(); if ($code !== 354) return $bye('سرور آمادهٔ دریافت متن نشد.');
    fwrite($fp, preg_replace('/^\./m', '..', $data) . "\r\n.\r\n"); [$code, $resp] = $rd();
    @fwrite($fp, "QUIT\r\n"); @fclose($fp);
    return $code === 250 ? ['ok' => true, 'msg' => 'ارسال شد.'] : ['ok' => false, 'msg' => 'سرور نامه را نپذیرفت: ' . trim($resp)];
}
