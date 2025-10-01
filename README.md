# SSH Audit Tool 🔐

A simple Python script to analyze your **`sshd_config`** file and report potential security issues.

## Features
- Detects missing SSH configuration keys
- Warns about insecure settings (e.g. X11Forwarding)
- Prints effective configuration from `sshd -T`
- Easy to use and lightweight

## Usage
```bash
sudo python3 Read_ssh_tool.py

Example Output:
[MISSING] PermitRootLogin
[MISSING] PasswordAuthentication
[WARN]    X11Forwarding = yes
