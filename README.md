# Mr.Kanakku Pillai - a private, offline ledger for one person

## What it is
- One person, one device (or several, moved by backup and restore). No server, no account, no sharing, no internet needed.
- 4-digit PIN, then profile, then the app. The PIN locks the app again after 15 minutes of not using it (away in another app, or open but untouched). 5 wrong tries = 5 min lock, longer after more.
- Personal / Official accounts, folders (long-press an account to move it into a folder), credit / debit, balances in integer paise, "by <name>" on every entry.
- Cash-book table for every account and for All transactions: blue header, green month bars, oldest first, running balance.
- Tap an entry to Edit or Delete it. Tap the account or folder name (with the pencil) to rename it.
- **Select and add up:** long-press an entry (in an account or in All transactions) to start selecting, tap more entries to add or remove them, or use the select-all button at the top. The bar at the bottom shows the total Credit, Debit and Net of the selected entries and changes as you select or deselect. Cross or back button finishes.
- Export to Excel / PDF / CSV (on a phone the file is handed to the system send-file screen; the files are NOT encrypted).
- All data is AES-256-GCM encrypted on the device; the data key is wrapped by your PIN and a recovery code and tied to the OS keystore.
- Encrypted backup / restore in Settings: this is how you move your data to another phone or PC.

## Build without installing anything (GitHub Actions, free)
1. Create a free GitHub account, then a new **private** repository.
2. Upload the contents of this folder (including the hidden `.github` folder) to the repo root.
3. Open the repo -> **Actions** tab -> **build** -> **Run workflow**.
4. After ~10 minutes, open the finished run and download from **Artifacts**: `android-apk` (install on phone), `windows-app`, `linux-app`.

### Updating the installed app without losing data
Without a fixed signing key every build is signed with a random key and Android refuses to install it over the old app (you would have to uninstall, which deletes the data). Fix it once:
1. Run the **make-signing-key** workflow, copy the text from its run summary into a repository secret named `DEBUG_KEYSTORE_BASE64`, then delete that run.
2. Run **build**. Builds now get an increasing build number and install over the old app.

## Run / build locally (needs the Flutter SDK)
    flutter create --platforms=android,ios,windows,linux .   # one time: generates platform folders
    flutter pub get
    flutter run
    flutter build apk --release      # Android
    flutter build windows --release  # on Windows
    flutter build linux --release    # on Linux (needs: sudo apt install clang cmake ninja-build libgtk-3-dev libsecret-1-dev)

## History
- v11: removed Firebase / sync and every sharing feature (the app is for one person). Added select-and-add-up. 
- v10: fixed auto-lock firing while working inside an account (touches anywhere now count), safer saving.
- v9: fixed signing key + build number for in-place updates.
- v7: ledger-table look. v4: PIN + device-bound key, lockout.
