# Invora — notes for contributors (and Claude)

- The whole UI lives in `app.html` (offline and web share it). PHP (`index.php`, `api.php`, `d.php`, `inc/`) is the web backend.
- Every change that ships must:
  1. bump `<meta name="app-version" content="X.Y.Z">` in `app.html` (the single source of the version);
  2. add an entry at the top of `APP_CHANGES` in `app.html` (Persian, user-facing, date in Jalali `YYYY/MM/DD`);
  3. list any new deployable file in `deploy-files.txt` (paths at most one folder deep; never `inc/config.local.php` or `*.ini`).
- Pushing to `main` is a release: running sites check GitHub every few minutes and install it automatically
  (`inc/update.php`: syntax check → backup → install → health check → rollback). Keep `index.php?df_health=1`,
  `api.php` (GET → JSON `{"error":"method"}`) and `d.php` (no token → 4xx page) working, or every update rolls back.
- Never read or write user data in plaintext on the server: use `df_sread/df_swrite` and `df_enc/df_dec` (`inc/crypto.php`).
- Old data must keep loading: extend `migrate()` / `fixDoc()` in `app.html` when the state shape changes.
- Before pushing: `php -l` all PHP files, extract the `<script>` blocks of `app.html` and `node --check` them, and run the UI tests.
