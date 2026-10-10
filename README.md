<p align="center">
  <img src="assets/logo.png" width="120" alt="Poof logo">
</p>

<h1 align="center">Poof</h1>

<p align="center">
  Remove programs completely. Fast, tiny, free.<br>
  <a href="https://github.com/EL4CTEO/poof/releases/latest"><b>Download</b></a>
</p>

## What it does

- Lists your programs and Store apps, with instant search
- Uninstalls them, then finds leftover files and settings so you can remove those too
- Removes broken entries that won't uninstall
- Safe: you review everything first, files go to the Recycle Bin, settings are backed up

## How to use

1. Open `poof.exe` (no install needed)
2. Select a program and press **Uninstall**
3. Review the leftovers and press **Remove selected**

Tip: for a deeper cleanup, choose **More → Run as administrator**.

Shortcuts: `Ctrl+F` search · `Enter` uninstall · `F5` refresh

## Requirements

Windows 10 or 11 (64-bit).

Logs and backups are saved in `%LOCALAPPDATA%\Poof`.

## Build

```
cargo build --release
```

## License

MIT
