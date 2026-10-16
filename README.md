# PS4 PKG Unpacker (Drag & Drop)

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Platform Windows](https://img.shields.io/badge/Platform-Windows-0078D6.svg)](https://www.microsoft.com/windows)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A lightweight, high-performance **PlayStation 4 PKG Unpacker** with a simple Windows **Drag & Drop** interface.

It handles official/retail PKG structures and Fake PKGs (FPKG), decrypting outer package metadata and decompressing the nested PlayStation FileSystem (`PFS`/`PFSC`) into ready-to-use game assets.

---

## ✨ Features

* 🖱️ **Zero Setup Drag & Drop:** Drag any `.pkg` file directly onto `Drag_Drop_Unpack_PKG.bat`.
* 🔍 **Smart Package Detection:** Automatically detects whether a file is a **Fake PKG (FPKG)** or an **Official Sony Retail PKG (PSN)**.
* 🎮 **Full Fake PKG (FPKG) Unpacking:** Fully decrypts and extracts all outer system files and inner game files (`eboot.bin`, game data, assets, WADs, audio, textures).
* 🛡️ **Retail Package & Passcode Support:** Extracts all 49+ package metadata files, DDS textures, TRP trophies, background artwork, sounds, and changelogs. If a 32-character game passcode is provided (`-p/--passcode` or interactive prompt), decrypts the game partition as well.
* 🔐 **SC Entry Decryption:** Decrypts encrypted system files like `nptitle.dat` and `npbind.dat` using `DK3`.
* 🌍 **Full Unicode & Multilingual Support:** Correctly prints non-ASCII game titles (Arabic, Japanese, Chinese, Cyrillic, etc.) without terminal encoding errors.
* ⚡ **Fast In-Process Unpacking:** No complex compilation needed; uses pure Python with hardware-accelerated cryptographic primitives (`cryptography`).

---

## 🎮 How to Use

### Method 1: Drag & Drop (Recommended)
1. Select any PS4 `.pkg` file in Windows Explorer.
2. Drag and drop it onto **`Drag_Drop_Unpack_PKG.bat`**.
3. The unpacked folder will be created automatically in the same folder as the `.pkg` file.

### Method 2: Command Line (CLI)
You can run the Python script directly from your terminal:
```bash
python unpack_ps4_pkg.py "C:\path\to\game.pkg"
```

To provide a 32-character game passcode for a retail or custom package:
```bash
python unpack_ps4_pkg.py "C:\path\to\game.pkg" -p "0123456789ABCDEF0123456789ABCDEF"
```

To specify an output directory or dump raw PFS containers:
```bash
python unpack_ps4_pkg.py "game.pkg" -o "C:\ExtractedGame" --dump-pfs
```

---

## 💡 Fake PKGs (fPKG) vs Official Retail PKGs

* **Fake PKGs (fPKG / Homebrew Dumps):**
  Packages dumped from a jailbroken PS4 console (e.g. using Itemzflow or PS4-dumper). These use community keys or standard passcodes, allowing 100% full extraction of all game executables (`eboot.bin`), models, textures, and data files on any PC.
* **Official Retail PKGs (PSN CDN / Sony Downloads):**
  Official packages downloaded from Sony's PlayStation Network. The outer system files (artwork, icons, sound, patch notes, trophies, `param.sfo`) are fully extracted by this tool. The inner game assets are hardware-encrypted by Sony's proprietary SAMU processor chip inside physical PS4 consoles and require either the 32-character developer passcode or dumping on a jailbroken console.


---

## 📁 Extracted Directory Structure

```text
Game_Title/
├── eboot.bin                # Decrypted game executable (SELF/ELF)
├── sce_discmap.plt          # Disc map file
├── sce_discmap_patch.plt    # Patch map file
├── EXEC/                    # Game assets, WADs, archives, data
│   └── ...
└── sce_sys/                 # Package metadata
    ├── param.sfo            # Title, Version, Category, ID info
    ├── icon0.png            # Game icon
    ├── pic0.png             # Game background banner
    ├── pic1.png             # Game background splash
    └── changeinfo/          # Version changelog XMLs
```

---

## 🛠️ How It Works (Technical Details)

1. **Header Inspection:** Reads the 0x7F434E54 magic header, parses the package table offset, file entries, and content ID.
2. **Metadata Extraction:** Extracts unencrypted outer system files into `sce_sys/` and inspects `param.sfo`.
3. **Crypto Pipeline:**
   * Reads Entry `0x10` (`ENTRY_KEYS`) and performs RSA PKCS#1 v1.5 decryption on `key1[3]` using `PkgDerivedKey3Keyset` to retrieve `DK3`.
   * Computes SHA-256 over `Entry 0x20 Header + DK3` to produce `ivKey`.
   * Decrypts Entry `0x20` with AES-128-CBC, then decrypts the payload with `FakeKeyset` RSA to recover `EKPFS`.
   * Derives `tweakKey` and `dataKey` via HMAC-SHA256 (`seed` + index `1`).
4. **PFS Image Decryption:** Decrypts outer PFS sectors using derived keys and unpacks `pfs_image.dat`.
5. **Payload Decompression:** Decompresses zlib/PFSC sector streams into final files.

---

## 🤝 Credits & Acknowledgements
* [shadPS4 Project](https://github.com/shadps4-emu/shadPS4) & [ps4-pkg-tools](https://github.com/xXJSONDeruloXx/ps4-pkg-tools) for PlayStation 4 reverse engineering documentation and key specifications.
* [flatz](https://github.com/flatz) for pioneer PS4 PFS and PKG tools.
* [PSBrew/MkPFS](https://github.com/PSBrew/MkPFS) for PFS image parsing foundations.

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
