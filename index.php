<?php
/* دفتر فاکتور — نسخه‌ی تحت وب: ورود و نمایش برنامه.
   خود برنامه فقط در app.html است؛ همان فایلی که به‌صورت آفلاین هم باز می‌شود. */
declare(strict_types=1);
define('DF', 1);
require __DIR__ . '/inc/lib.php';

/* used by the auto-updater to verify the site still works after installing a new version */

df_headers('app');
if (!df_crypto_ok()) { http_response_code(500); df_page('دفتر فاکتور', '<h1>نیاز به OpenSSL</h1><div class="err">برای رمزنگاری اطلاعات، افزونه‌ی openssl در PHP لازم است (با پشتیبانی aes-256-gcm). در سی‌پنل از «Select PHP Version» آن را فعال کنید.</div>'); exit; }
df_session_start();
$users = df_users();
/* health check used by the self-updater after installing a new version */
if (isset($_GET['df_health'])) {
    header('Content-Type: text/plain; charset=utf-8'); header('Cache-Control: no-store');
    $a = (string)@file_get_contents(__DIR__ . '/app.html');
    $ok = $a !== '' && stripos($a, '</head>') !== false && df_app_version($a) !== '' && is_writable(df_data_dir());
    if (!$ok) http_response_code(500);
    echo ($ok ? 'ok ' : 'fail ') . df_app_version($a); exit;
}
$err = '';
$mode = (string)($_GET['m'] ?? '');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $act = (string)($_POST['act'] ?? '');
    if (!df_csrf_ok((string)($_POST['csrf'] ?? ''))) {
        $err = 'مهلت فرم تمام شده بود؛ دوباره امتحان کنید.';
    } elseif ($act === 'setup' && !$users) {
        $u = trim((string)($_POST['u'] ?? ''));
        $p = (string)($_POST['p'] ?? '');
        if ($p !== (string)($_POST['p2'] ?? '')) $err = 'تکرار رمز عبور یکسان نیست.';
        elseif (df_has_dek()) {
            /* users file was lost but encrypted data exists: the recovery code is needed */
            $dek = !empty(df_keys()['rk']) ? df_unwrap(df_keys()['rk'], df_rc_norm((string)($_POST['rc'] ?? ''))) : null;
            if ($dek === null) $err = 'کد بازیابی اشتباه است.';
            elseif ($e = df_user_add($u, $p, true, $dek)) $err = $e;
            elseif ($e = df_login($u, $p)) $err = $e;
            else { header('Location: ' . df_base_path()); exit; }
        }
        elseif ($e = df_user_add($u, $p, true, null)) $err = $e;
        elseif ($e = df_login($u, $p)) $err = $e;
        else { header('Location: ' . df_base_path()); exit; }
    } elseif ($act === 'login') {
        $e = df_login(trim((string)($_POST['u'] ?? '')), (string)($_POST['p'] ?? ''));
        if ($e) $err = $e; else { header('Location: ' . df_base_path()); exit; }
    } elseif ($act === 'recover') {
        $mode = 'recover';
        $p = (string)($_POST['p'] ?? '');
        if ($p !== (string)($_POST['p2'] ?? '')) $err = 'تکرار رمز عبور یکسان نیست.';
        elseif ($e = df_recover(trim((string)($_POST['u'] ?? '')), (string)($_POST['rc'] ?? ''), $p)) $err = $e;
        else { header('Location: ' . df_base_path()); exit; }
    } elseif ($act === 'rc_ack') {
        df_sess_del('rc');
        header('Location: ' . df_base_path()); exit;
    } elseif ($act === 'logout') {
        df_logout();
        header('Location: ' . df_base_path()); exit;
    }
    $users = df_users();
}
$form = fn(string $act, string $inner) => '<form method="post" autocomplete="off" style="display:flex;flex-direction:column;gap:10px"><input type="hidden" name="act" value="' . $act . '"><input type="hidden" name="csrf" value="' . df_h(df_csrf()) . '">' . $inner . '</form>';
$errBox = $err ? '<div class="err">' . df_h($err) . '</div>' : '';
$passFields = '<label>رمز عبور (دست‌کم ۸ نویسه)<input name="p" type="password" dir="ltr" required minlength="8" autocomplete="new-password"></label>'
    . '<label>تکرار رمز عبور<input name="p2" type="password" dir="ltr" required minlength="8" autocomplete="new-password"></label>';

if (!$users) {
    $needRc = df_has_dek();
    df_page('راه‌اندازی دفتر فاکتور', '<h1>راه‌اندازی دفتر فاکتور</h1><p class="muted">' . ($needRc
            ? 'اطلاعات رمزشده‌ی قبلی روی سرور هست ولی فهرست کاربران پیدا نشد. برای دسترسی دوباره، «کد بازیابی» را وارد کنید و حساب مدیر تازه بسازید.'
            : 'هنوز کاربری ساخته نشده است. نام کاربری و رمز عبور مدیر را تعیین کنید. همه‌ی اطلاعات با کلیدی رمز می‌شوند که با همین رمز باز می‌شود.') . '</p>'
        . $errBox . $form('setup', '<label>نام کاربری (حروف انگلیسی)<input name="u" dir="ltr" required minlength="3" maxlength="32" pattern="[A-Za-z0-9_.\-]{3,32}"></label>' . $passFields
        . ($needRc ? '<label>کد بازیابی<input name="rc" dir="ltr" required autocomplete="off"></label>' : '') . '<button>ساخت حساب مدیر</button>'));
    exit;
}

if (!df_logged_in()) {
    if ($mode === 'recover') {
        df_page('بازیابی رمز', '<h1>تعیین رمز تازه با کد بازیابی</h1><p class="muted">کد بازیابی همان کدی است که هنگام راه‌اندازی (یا از «تنظیمات عمومی») به مدیر نشان داده شد.</p>' . $errBox
            . $form('recover', '<label>نام کاربری<input name="u" dir="ltr" required></label><label>کد بازیابی<input name="rc" dir="ltr" required placeholder="XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"></label>' . $passFields . '<button>تعیین رمز و ورود</button>')
            . '<p class="muted"><a href="' . df_h(df_base_path()) . '">بازگشت به ورود</a></p>');
        exit;
    }
    $pkOn = df_pk_any(); $smsOn = !empty(sms_cfg()['login']);
    $alt = '';
    if ($pkOn || $smsOn) {
        $alt = '<div id="xMsg" class="muted" hidden></div>'
            . ($pkOn ? '<button type="button" id="pkBtn" hidden style="background:#fff;color:#1e5a55;border:1px solid #1e5a55">ورود با اثر انگشت / چهره</button>' : '')
            /* «ورود با کد پیامکی»: فرمِ رمز، اثر انگشت و پانویس پنهان می‌شوند و فقط نام کاربری و کد می‌ماند (انتخاب در همین مرورگر به یاد می‌ماند) */
            . ($smsOn ? '<button type="button" id="smsOpen" style="background:#fff;color:#1e5a55;border:1px solid #1e5a55">ورود با کد پیامکی</button><div id="smsBox" style="display:none;flex-direction:column;gap:10px">'
                . '<label>نام کاربری<input id="smsU" dir="ltr" autocomplete="username"></label><div id="capBox" hidden style="display:flex;flex-direction:column;gap:6px"><span style="font-size:13px">بررسی امنیتی: عددهای تصویر را بنویسید <small class="muted">(اگر جمع است، حاصل را)</small></span>'
                . '<div style="display:flex;gap:8px;align-items:center"><img id="capImg" alt="" width="200" height="64" style="border-radius:8px;border:1px solid #c9cfcb;background:#f6f7f5"><button type="button" id="capNew" title="تصویر تازه" style="background:#fff;color:#1e5a55;border:1px solid #1e5a55;padding:6px 10px">↻</button></div>'
                . '<input id="capIn" class="pin" inputmode="numeric" autocomplete="off" maxlength="8"></div>'
                . '<button type="button" id="smsSend">فرستادن کد</button>'
                . '<label id="smsCodeL" hidden>کد پیامک‌شده<input id="smsCode" class="pin" inputmode="numeric" autocomplete="one-time-code" maxlength="400"></label><button type="button" id="smsGo" hidden>ورود</button>'
                . '<div style="display:flex;justify-content:space-between;gap:8px;font-size:13px"><a href="#" id="smsBack">← ورود با رمز</a><a href="#" id="smsPaste" hidden>چسباندن کدِ کپی‌شده</a></div></div>' : '')
            . '<script>(function(){var C=(document.querySelector("input[name=csrf]")||{}).value||"";'
            . 'function b2(s){s=s.replace(/-/g,"+").replace(/_/g,"/");while(s.length%4)s+="=";var b=atob(s),u=new Uint8Array(b.length);for(var i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u.buffer}'
            . 'function u2(b){b=new Uint8Array(b);var s="";for(var i=0;i<b.length;i++)s+=String.fromCharCode(b[i]);return btoa(s).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/,"")}'
            . 'function post(d){return fetch("auth.php",{method:"POST",credentials:"same-origin",headers:{"Content-Type":"application/json","X-CSRF-Token":C},body:JSON.stringify(d)}).then(function(r){return r.json().catch(function(){return{ok:false,error:"پاسخ سرور خوانده نشد؛ صفحه را تازه کنید."}})})}'
            . 'var M=document.getElementById("xMsg");function say(t,bad){M.textContent=t||"";M.className=bad?"err":"muted";M.hidden=!t}'
            . 'var pk=document.getElementById("pkBtn");'
            . 'if(pk&&window.PublicKeyCredential&&navigator.credentials&&window.isSecureContext){pk.hidden=false;pk.onclick=function(){say("اثر انگشت یا چهره را روی دستگاه تأیید کنید…");'
            . 'post({a:"pk_options"}).then(function(r){if(!r.ok)throw new Error(r.error);var o=r.options;o.challenge=b2(o.challenge);(o.allowCredentials||[]).forEach(function(c){c.id=b2(c.id)});return navigator.credentials.get({publicKey:o})})'
            . '.then(function(c){if(!c)throw new Error("پاسخی از دستگاه نیامد.");var R=c.response;return post({a:"pk_login",cred:{id:c.id,clientDataJSON:u2(R.clientDataJSON),authenticatorData:u2(R.authenticatorData),signature:u2(R.signature)}})})'
            . '.then(function(r){if(!r.ok)throw new Error(r.error);location.href=r.go})'
            . '.catch(function(e){say(e&&(e.name==="NotAllowedError"||e.name==="AbortError")?"انجام نشد یا لغو شد. اگر اثر انگشت این دستگاه را ثبت نکرده‌اید، با رمز وارد شوید و از «تنظیمات عمومی ← حساب کاربری» ثبتش کنید.":(e&&e.message)||"انجام نشد.",true)})}}'
            . 'var sb=document.getElementById("smsSend");if(sb){sb.onclick=function(){var u=document.getElementById("smsU").value.trim();if(!u){say("نام کاربری را بنویسید.",true);return}sb.disabled=true;'
            . 'var cb=document.getElementById("capBox"),ci=document.getElementById("capIn");'
            . 'post({a:"otp_send",u:u,cap:cb.hidden?"":ci.value.trim()}).then(function(r){sb.disabled=false;'
            . 'if(r.captcha){cb.hidden=false;cb.style.display="flex";ci.value="";capLoad();ci.focus();say(r.error,true);return}cb.hidden=true;cb.style.display="none";if(!r.ok){say(r.error,true);return}say(r.msg+(r.show?" — حالت آزمایشی، کد: "+r.show:""));document.getElementById("smsCodeL").hidden=false;document.getElementById("smsGo").hidden=false;sb.textContent="فرستادن دوباره‌ی کد";sb.style.cssText="background:#fff;color:#1e5a55;border:1px solid #1e5a55";var spb=document.getElementById("smsPaste");if(spb&&navigator.clipboard&&navigator.clipboard.readText)spb.hidden=false;document.getElementById("smsCode").focus();otpAuto()})};'
            /* اندروید (Chrome): کد خودش از پیامک برداشته و وارد می‌شود (WebOTP) — خطِ آخرِ پیامک باید «@دامنه #کد» باشد؛ آیفون کد را بالای صفحه‌کلید پیشنهاد می‌دهد */
            . 'function capLoad(){document.getElementById("capImg").src="auth.php?a=captcha&r="+Date.now()}document.getElementById("capNew").onclick=capLoad;document.getElementById("capBox").style.display="none";'
            /* مثل وبی (assets/js/main.js): درخواستِ WebOTP فقط یک بار ساخته می‌شود و فقط با ترکِ صفحه لغو می‌شود —
               لغو و ساختِ دوباره (با هر «فرستادن کد» یا زدنِ «ورود») باعث می‌شد «Allow» به درخواستِ لغوشده برسد و کد پر نشود.
               عیب‌یابی: صفحه را با ?otpdebug=1 باز کنید تا گزارشِ مرحله‌به‌مرحله پایین صفحه دیده شود. */
            . 'var DBG=/[?&]otpdebug=1/.test(location.search),lg=function(){};if(DBG){var bx=document.createElement("div");bx.style.cssText="position:fixed;z-index:9999;left:8px;right:8px;bottom:8px;max-height:45vh;overflow:auto;background:#0D1620;color:#7CFF9B;font:12px/1.7 monospace;padding:10px 12px;border-radius:10px;direction:ltr;text-align:left;white-space:pre-wrap";document.body.appendChild(bx);lg=function(m){bx.textContent+=m+"\\n";bx.scrollTop=bx.scrollHeight};lg("--- OTP debug ---");lg("origin: "+location.origin);lg("OTPCredential: "+("OTPCredential" in window));lg("UA: "+navigator.userAgent.slice(0,90))}'
            . 'var otpOn=false;function otpAuto(){if(otpOn){lg("WebOTP already waiting");return}if(!("OTPCredential" in window)||!navigator.credentials){lg("WebOTP unavailable in this browser");return}if(!window.isSecureContext){lg("WebOTP skipped: page is not https");return}'
            . 'otpOn=true;var ac=new AbortController();window.addEventListener("pagehide",function(){ac.abort()});lg("requesting SMS code…");'
            . 'navigator.credentials.get({otp:{transport:["sms"]},signal:ac.signal}).then(function(o){otpOn=false;lg("resolved: "+JSON.stringify(o&&o.code));var c=otpNorm(o&&o.code);lg("cleaned: "+c);if(!c){say("پیامک خوانده شد ولی کدی در خط آخرش پیدا نشد؛ کد را دستی بنویسید.",true);return}'
            . 'var ic=document.getElementById("smsCode");document.getElementById("smsCodeL").hidden=false;ic.focus();ic.value=c;try{ic.dispatchEvent(new Event("input",{bubbles:true}));ic.dispatchEvent(new Event("change",{bubbles:true}))}catch(e){}'
            . 'say("کد از پیامک خوانده شد؛ در حال ورود…");setTimeout(function(){document.getElementById("smsGo").click()},60)})'
            . '.catch(function(e){otpOn=false;lg("rejected: "+(e&&e.name)+" — "+(e&&e.message));if(e&&e.name!=="AbortError")say("خواندن خودکار کد انجام نشد ("+(e.name||"")+")؛ کد را بنویسید یا متن پیامک را این‌جا بچسبانید.",true)})}'
            /* کد: رقم‌های فارسی/عربی هم؛ از متنِ کاملِ پیامک (چسبانده یا خوانده‌شده) آخرین عددِ ۴ تا ۸ رقمی */
            . 'function otpNorm(x){var s=String(x||"").replace(/[\u06F0-\u06F9]/g,function(d){return d.charCodeAt(0)-1776}).replace(/[\u0660-\u0669]/g,function(d){return d.charCodeAt(0)-1632});var m=s.match(/\d{4,8}/g);return m?m[m.length-1]:""}'
            . 'var sbx=document.getElementById("smsBox");if(sbx){var pwb=document.getElementById("pwBox"),h1=document.getElementById("lgH"),so=document.getElementById("smsOpen"),pkb=document.getElementById("pkBtn");'
            . 'var smsMode=function(on){var ft=document.getElementById("lgFoot");pwb.style.display=on?"none":"";so.style.display=on?"none":"";if(ft)ft.style.display=on?"none":"";if(pkb)pkb.style.display=on?"none":"";sbx.style.display=on?"flex":"none";h1.textContent=on?"ورود با کد پیامکی":"ورود به دفتر فاکتور";'
            . 'try{localStorage.setItem("df-login-sms",on?"1":"")}catch(e){}if(on){var su=document.getElementById("smsU"),pu=document.querySelector("#pwBox input[name=u]");if(pu&&pu.value&&!su.value)su.value=pu.value;(su.value?document.getElementById("smsSend"):su).focus()}};'
            . 'so.onclick=function(){smsMode(true)};document.getElementById("smsBack").onclick=function(e){e.preventDefault();smsMode(false)};var mem="";try{mem=localStorage.getItem("df-login-sms")||""}catch(e){}if(mem){smsMode(true);document.addEventListener("DOMContentLoaded",function(){smsMode(true)})}}'
            . 'var icx=document.getElementById("smsCode");icx.addEventListener("input",function(){var v=icx.value;if(/[^0-9]/.test(v)||v.length>8){var c=otpNorm(v);if(c&&c!==v){icx.value=c;if(c.length===5)document.getElementById("smsGo").click()}}});'
            . 'var pb=document.getElementById("smsPaste");if(pb){if(!(navigator.clipboard&&navigator.clipboard.readText))pb.hidden=true;pb.onclick=function(ev){if(ev)ev.preventDefault();navigator.clipboard.readText().then(function(t){var c=otpNorm(t);if(!c){say("در حافظه کدی پیدا نشد؛ اول کد یا متن پیامک را کپی کنید.",true);return}icx.value=c;document.getElementById("smsGo").click()}).catch(function(){say("اجازه‌ی خواندن حافظه داده نشد؛ کد را بنویسید.",true)})}}'
            . 'var goBusy=false;document.getElementById("smsGo").onclick=function(){if(goBusy)return;var cv=otpNorm(document.getElementById("smsCode").value);if(!cv){say("کد را بنویسید.",true);return}goBusy=true;lg("submitting "+cv);post({a:"otp_login",code:cv}).then(function(r){goBusy=false;lg("login: "+(r.ok?"ok":r.error));if(!r.ok){say(r.error,true);return}location.href=r.go},function(){goBusy=false})}}'
            . '})();</script>';
    }
    df_page('ورود به دفتر فاکتور', '<h1 id="lgH">ورود به دفتر فاکتور</h1>' . $errBox
        . '<div id="pwBox">' . $form('login', '<label>نام کاربری<input name="u" dir="ltr" required autocomplete="username webauthn" autofocus></label><label>رمز عبور<input name="p" type="password" dir="ltr" required autocomplete="current-password"></label><button>ورود</button>') . '</div>' . $alt
        . '<p class="muted" id="lgFoot">بعد از ' . df_fa_num((string)DF_LOGIN_MAX_FAILS) . ' بار رمز اشتباه، ورود ' . df_fa_num((string)DF_LOGIN_LOCK_MINUTES) . ' دقیقه بسته می‌شود. · <a href="?m=recover">رمز را فراموش کرده‌ام</a></p>');
    exit;
}

/* show a freshly created recovery code once */
if (($rc = df_sess_get('rc')) !== null) {
    df_page('کد بازیابی', '<h1>کد بازیابی را یادداشت کنید</h1>'
        . '<p>همه‌ی اطلاعات روی سرور رمزشده است و فقط با رمز عبور کاربران باز می‌شود. اگر رمز همه‌ی مدیرها فراموش شود، <b>تنها راه</b> دسترسی دوباره همین کد است:</p>'
        . '<div style="direction:ltr;text-align:center;font:700 19px/1.6 monospace;letter-spacing:.06em;background:#f1f4f2;color:#1d2321;border-radius:8px;padding:12px;user-select:all">' . df_h($rc) . '</div>'
        . '<p class="muted">این کد را روی کاغذ یا جای امنی بیرون از این سرور نگه دارید. دوباره نمایش داده نمی‌شود (مدیر می‌تواند از «تنظیمات عمومی» کد تازه بسازد که کد قبلی را باطل می‌کند).</p>'
        . $form('rc_ack', '<button>یادداشت کردم، ادامه</button>'));
    exit;
}

$app = @file_get_contents(__DIR__ . '/app.html');
if ($app === false) { http_response_code(500); exit('app.html not found'); }
$cfg = ['api' => df_base_path() . 'api.php', 'home' => df_base_path(), 'csrf' => df_csrf(), 'user' => $_SESSION['u'], 'admin' => !empty($_SESSION['admin']), 'perms' => !empty($_SESSION['admin']) ? null : (df_users()[$_SESSION['u']]['perms'] ?? null),
    'since' => (int)($_SESSION['since'] ?? 0) * 1000, 'prevLogin' => (int)($_SESSION['prev']['at'] ?? 0) * 1000, 'prevIp' => (string)($_SESSION['prev']['ip'] ?? ''), 'prevHow' => (string)($_SESSION['prev']['how'] ?? ''), 'how' => (string)($_SESSION['how'] ?? '')];
$inject = df_icon_links() . '<script>window.DF_SERVER=' . json_encode($cfg, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT) . ';</script>';
$pos = stripos($app, '</head>');
echo $pos === false ? $inject . $app : substr($app, 0, $pos) . $inject . substr($app, $pos);
