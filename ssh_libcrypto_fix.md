# 🛠️ Fixing `Load key "...": error in libcrypto` in SSH

## 1. 🚨 The Problem

We attempted to connect to a remote host using SSH with a `.pem` file:

```bash
ssh -i wdcs.pem wdcs-inhouse-prod-do@192.168.97.235
```

And encountered this error:

```text
Load key "wdcs.pem": error in libcrypto
Permission denied (publickey).
```

This means OpenSSH failed to parse the private key using OpenSSL's libcrypto due to **incompatible key format**.

### 🔎 Root Cause

- The key `wdcs.pem` was in **OpenSSH format** (`-----BEGIN OPENSSH PRIVATE KEY-----`)
- `libcrypto` expects **PEM/PKCS#1** format (`-----BEGIN RSA PRIVATE KEY-----`)
- OpenSSL-based tools cannot read OpenSSH keys directly

Our main goal: **Convert the private key to a format compatible with OpenSSL and SSH tools.**

---

## 2. 🔍 Key File Formats and Compatibility

| Format       | Header                                | Compatible with SSH? | Compatible with OpenSSL? |
| ------------ | ------------------------------------- | -------------------- | ------------------------ |
| OpenSSH      | `-----BEGIN OPENSSH PRIVATE KEY-----` | ✅ Yes                | ❌ No                     |
| PEM (PKCS#1) | `-----BEGIN RSA PRIVATE KEY-----`     | ✅ Yes                | ✅ Yes                    |
| PEM (PKCS#8) | `-----BEGIN PRIVATE KEY-----`         | ✅ Yes                | ✅ Yes                    |

### 🔍 File status before conversion:

```bash
ls -l
# wdcs.pem exists with OpenSSH format
head -n 1 wdcs.pem
# => -----BEGIN OPENSSH PRIVATE KEY-----
```

---

## 3. ✅ Step-by-Step Solution: Convert OpenSSH to PEM Format

### ✅ Step 1: Check file permission

```bash
chmod 600 wdcs.pem
```

Why: SSH refuses to use keys that are accessible to others for security.

### ✅ Step 2: Try inspecting the key using `openssl`

```bash
openssl rsa -in wdcs.pem -check
```

Result:

```text
Could not read private key from wdcs.pem
```

\=> Confirms format incompatibility

### ✅ Step 3: Convert the key using `ssh-keygen`

```bash
ssh-keygen -p -m PEM -f wdcs.pem -N ""
```

- `-m PEM`: convert to PKCS#1 format
- `-p`: change key passphrase (none in our case)
- `-f wdcs.pem`: input file
- `-N ""`: new passphrase is empty (for compatibility)

✅ **This replaces the file ****\`\`**** with new contents**:

```bash
head -n 1 wdcs.pem
# => -----BEGIN RSA PRIVATE KEY-----
```

We now have a proper PEM key compatible with both SSH and OpenSSL.

---

## 4. 🌐 Optional: Export to Separate File (Preserve Original)

If you want to preserve the original and write output to a **new file**, copy first:

```bash
cp wdcs.pem wdcs-openssh.pem
ssh-keygen -p -m PEM -f wdcs-openssh.pem -N ""
```

Result:

```bash
ls
# wdcs.pem (converted to PEM)
# wdcs-openssh.pem (backup copy)
```

---

## 5. 🧐 Final File Summary

| File               | Description        | Format       | Purpose                                      |
| ------------------ | ------------------ | ------------ | -------------------------------------------- |
| `wdcs.pem`         | Converted key file | PEM / PKCS#1 | Compatible with OpenSSL, libcrypto, SSH `-i` |
| `wdcs-openssh.pem` | Backup of original | OpenSSH      | Original incompatible version                |

---

## 6. 🧪 Troubleshooting Checklist

1. Check key header:

```bash
head -n 1 wdcs.pem
```

Should be `-----BEGIN RSA PRIVATE KEY-----`

2. Check file type:

```bash
file wdcs.pem
```

Should say: `PEM RSA private key`

3. If `ssh -i wdcs.pem` fails again:

- Ensure file is Unix-formatted: `dos2unix wdcs.pem`
- Ensure permission is correct: `chmod 600 wdcs.pem`
- Add verbose debug: `ssh -vvv -i wdcs.pem wdcs-inhouse-prod-do@host`

---

## 7. 📖 Real Context and Logs

### 🔎 Verbose SSH log fragment:

```text
debug1: identity file wdcs.pem type -1
debug1: Trying private key: wdcs.pem
Load key "wdcs.pem": error in libcrypto
debug1: No more authentication methods to try.
Permission denied (publickey).
```

### ✅ After conversion:

```text
debug1: identity file wdcs.pem type 1
debug1: Authentication succeeded (publickey).
```

---

## 8. 🔗 References

- [OpenSSH Key Format Explanation](https://blog.huque.com/2020/02/new-openssh-private-key-format.html)
- [ServerFault: Convert OpenSSH to PEM](https://serverfault.com/questions/854208)
- [OpenSSL and PEM format](https://www.openssl.org/docs/manmaster/man1/openssl-rsa.html)

---

## 📆 Final Summary

To fix `error in libcrypto`, convert the OpenSSH private key to PEM (PKCS#1) format using `ssh-keygen`:

```bash
ssh-keygen -p -m PEM -f wdcs.pem -N ""
```

Validate using:

```bash
file wdcs.pem
head -n 1 wdcs.pem
chmod 600 wdcs.pem
```

Your key is now compatible with SSH and OpenSSL tools without throwing errors from `libcrypto`.

