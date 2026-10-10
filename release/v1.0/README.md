# EntropyProbe v1.0

The `entropyprobe.cap` in this folder is the exact file installed on cards. It is not rebuilt and it is not touched.

| | |
|---|---|
| Package | `ENTROPY`, AID `454E54524F5059`, version 1.0 |
| Applet | AID `454E54524F505901` |
| Source | commit `7b06cfe`, 2026-08-28. `src/` and `build.sh` have not changed since |
| File SHA-256 | `b4023220a2cf8d8c3b81ed2ef877ff35dfdd6b5203a12caa821125ac512c413d` |
| Component fingerprint | `973dfaf417e4cb011b601aa4460ea0651dc3b04385c011585cb23bdf6bfe1fbe` |

**Checked on 2026-10-09** by building `7b06cfe` outside the repository with its `build.sh`: it gives this same component fingerprint, so this file is what that source produces.

The component fingerprint of any copy:

```
python -c "import zipfile,hashlib,sys; z=zipfile.ZipFile(sys.argv[1]); n=sorted(x for x in z.namelist() if '/javacard/' in x and x.endswith('.cap')); print(hashlib.sha256(b''.join(z.read(x) for x in n)).hexdigest())" entropyprobe.cap
```
