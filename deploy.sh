#!/bin/bash
# استقرار Invora روی هاست سی‌پنل — از .cpanel.yml صدا زده می‌شود (پوشه‌ی جاری = پوشه‌ی مخزن)
# مقصد به این ترتیب پیدا می‌شود:
#   1) مسیر خط اول فایل ‎~/.invora-deploy‎ (اگر باشد)
#   2) ‎~/invora‎ (اگر وجود داشته باشد)
#   3) تنها پوشه‌ای در خانه‌ی هاست که نامش با invora. شروع می‌شود (مثلاً ‎~/invora.example.com‎)
# پوشه‌ی داده، inc/config.local.php و بخش‌های ساخته‌شده‌ی سی‌پنل در .htaccess دست نمی‌خورند.
set -euo pipefail
REPO="$(cd "$(dirname "$0")" && pwd)"
H="${HOME:-}"
if [ -z "$H" ] || [ ! -d "$H" ]; then H="$(cd "$REPO/../.." && pwd)"; fi

DEST=""
CFG="$H/.invora-deploy"; [ -s "$CFG" ] || CFG="$REPO/.invora-deploy"
if [ -s "$CFG" ]; then
  DEST="$(head -n1 "$CFG" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's:/*$::')"
  echo "مقصد از $CFG: $DEST"
elif [ -d "$H/invora" ]; then
  DEST="$H/invora"
else
  shopt -s nullglob; c=("$H"/invora.*/); shopt -u nullglob
  if [ "${#c[@]}" -eq 1 ]; then DEST="${c[0]%/}"; fi
fi
if [ -z "$DEST" ]; then
  echo "خطا: پوشه‌ی مقصد پیدا نشد. فایل ~/.invora-deploy را با مسیر Document Root زیردامنه بسازید." >&2; exit 1
fi
case "$DEST" in
  "$H"/*) ;;
  *) echo "خطا: مقصد ($DEST) باید داخل پوشه‌ی خانه ($H) باشد." >&2; exit 1 ;;
esac
if [ "$DEST" = "$H" ] || [ "$DEST" = "$H/public_html" ] || [ "${DEST#"$H"/repositories}" != "$DEST" ]; then
  echo "خطا: مقصد ($DEST) مجاز نیست؛ باید پوشه‌ی مخصوص زیردامنه باشد." >&2; exit 1
fi
[ -d "$DEST" ] || { echo "خطا: پوشه‌ی مقصد ($DEST) وجود ندارد." >&2; exit 1; }

cd "$REPO"
# copy every file listed in deploy-files.txt (except .htaccess, merged below)
while IFS= read -r f || [ -n "$f" ]; do
  f="$(printf '%s' "$f" | tr -d '\r' | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"
  case "$f" in ""|\#*|.htaccess) continue ;; esac
  case "$f" in *..*|/*|inc/config.local.php) echo "مسیر نامعتبر: $f" >&2; exit 1 ;; esac
  mkdir -p "$DEST/$(dirname "$f")"
  cp -f "$f" "$DEST/$f"
  chmod 644 "$DEST/$f"
done < deploy-files.txt
# .htaccess: rules of the app + keep blocks that cPanel/LiteSpeed generated (# BEGIN … # END …)
TMP="$DEST/.htaccess.invora.$$"
{
  cat .htaccess
  if [ -f "$DEST/.htaccess" ]; then
    printf '\n'
    awk '/^#[[:space:]]*(php -- )?BEGIN /{p=1} p{print} /^#[[:space:]]*(php -- )?END /{p=0}' "$DEST/.htaccess"
  fi
} > "$TMP"
mv -f "$TMP" "$DEST/.htaccess"
chmod 644 "$DEST/.htaccess"
# record which commit is installed (shown in the app and used by the auto-updater)
SHA="$(git rev-parse HEAD 2>/dev/null || echo '')"
VER="$(grep -o '<meta name="app-version" content="[^"]*"' app.html | head -n1 | sed 's/.*content="//;s/"$//')"
printf '{"sha":"%s","version":"%s","at":%s,"by":"cpanel"}\n' "$SHA" "$VER" "$(date +%s)" > "$DEST/inc/release.json"
chmod 644 "$DEST/inc/release.json"
echo "Invora در $DEST مستقر شد."
