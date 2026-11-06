<?php
/* تنظیمات نسخه‌ی تحت وب «دفتر فاکتور»
   این فایل جزو مخزن است و با هر به‌روزرسانی از گیت‌هاب بازنویسی می‌شود.
   برای تغییر تنظیمات روی هاست، فایل inc/config.local.php را بسازید و فقط همان تعریف‌هایی را که می‌خواهید در آن بنویسید، مثلاً:
     <?php define('DF_NAVASAN_KEY', 'کلید شما');
   آن فایل در مخزن نیست و با به‌روزرسانی دست نمی‌خورد. */
if (!defined('DF')) { http_response_code(403); exit; }
if (is_file(__DIR__ . '/config.local.php')) require __DIR__ . '/config.local.php';

/* محل نگهداری اطلاعات روی هاست.
   خالی = خودکار: اگر بشود، پوشه‌ی «daftar-factor-data» کنار public_html (بیرون از دسترس وب) ساخته می‌شود؛
   وگرنه پوشه‌ی data داخل همین برنامه با دسترسیِ بسته.
   می‌توانید مسیر کامل دلخواه بدهید، مثلاً: '/home/USERNAME/daftar-factor-data' */
defined('DF_DATA_DIR') || define('DF_DATA_DIR', '');

/* اگر کاربر این‌قدر دقیقه کاری نکند، خودکار خارج می‌شود */
defined('DF_IDLE_MINUTES') || define('DF_IDLE_MINUTES', 120);
/* حداکثر طول یک ورود (ساعت)، حتی اگر کاربر فعال باشد */
defined('DF_MAX_SESSION_HOURS') || define('DF_MAX_SESSION_HOURS', 12);

/* قفل ورود: بعد از این تعداد رمز اشتباه، ورود از آن آی‌پی/نام کاربری برای چند دقیقه بسته می‌شود */
defined('DF_LOGIN_MAX_FAILS') || define('DF_LOGIN_MAX_FAILS', 5);
defined('DF_LOGIN_LOCK_MINUTES') || define('DF_LOGIN_LOCK_MINUTES', 15);

/* لینک اشتراک: بعد از وارد کردن رمز درست، تا این چند دقیقه می‌شود فایل را دید و دانلود کرد */
defined('DF_SHARE_PASS_MINUTES') || define('DF_SHARE_PASS_MINUTES', 30);
/* هر آی‌پی در یک ساعت حداکثر این تعداد رمز اشتباه (روی همه‌ی لینک‌ها) می‌تواند بزند */
defined('DF_SHARE_IP_MAX_FAILS_PER_HOUR') || define('DF_SHARE_IP_MAX_FAILS_PER_HOUR', 30);

/* نرخ دلار: تعداد پیش‌فرضِ دریافت از اینترنت در روز (از «تنظیمات عمومی ← نرخ دلار» قابل تغییر است) */
defined('DF_RATE_MAX_FETCH_PER_DAY') || define('DF_RATE_MAX_FETCH_PER_DAY', 2);
/* اختیاری: کلید API سایت navasan.tech (اگر خالی باشد از tgju.org خوانده می‌شود) */
defined('DF_NAVASAN_KEY') || define('DF_NAVASAN_KEY', '');
