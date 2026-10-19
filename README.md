# fidroh: secure authentication using fido2 + iroh protocols

Private tunnels over [iroh](https://iroh.computer), unlocked by an enrolled device **and** a FIDO2 security key.

Reach a web app on your home server from anywhere, with no open ports, no reverse proxy, and no third party that can read your traffic. A laptop gets in only if it holds an enrolled device key *and* you touch an enrolled security key (with its PIN).

> **Status:** early (v0.1). Works end to end; not yet audited. Use for personal infrastructure, not for anything you'd bet a company on.

## How it works

```text
browser → 127.0.0.1:8443 (fidroh connect) → iroh/QUIC → fidroh serve → 127.0.0.1:4000 (your app)
```

1. The laptop dials the server by its **endpoint id** (a public key). iroh punches through NAT, or falls back to an encrypted relay.
2. The server drops any laptop whose endpoint id isn't enrolled, before anything else happens.
3. The server sends a fresh challenge. The laptop's security key signs it, together with **both endpoint ids**, so a signature is useless from another laptop or against another server.
4. The server verifies the signature (ES256 or EdDSA), the PIN and touch flags, and a rising sign counter.
5. Each browser connection becomes its own QUIC stream, forwarded to your app.

## What it protects against

| Threat | Stopped by |
| --- | --- |
| A stranger finds the server's id | Device allowlist; unknown laptops never get a challenge |
| Stolen laptop, no security key | FIDO2 signature required |
| Stolen security key, no laptop | Credentials are bound to one enrolled laptop |
| Stolen key, PIN unknown | PIN required; the key locks after 8 wrong tries |
| Replayed login | Fresh challenge each time, and the sign counter must rise |
| Login relayed to another server | The signature covers the server's id |
| Eavesdropping, including relays | End-to-end QUIC/TLS 1.3 between the two endpoints |

**Not covered:** malware on the laptop while a session is open; a compromised server host; bugs in your app's own login.

## Install

You need Rust (via [rustup](https://rustup.rs)) and a C compiler (`build-essential` on Debian/Ubuntu).

**Laptop** (talks to the security key; on Linux also needs `libudev-dev` and `pkg-config`):

```bash
cargo install --path .
```

**Server** (no security key needed; builds without USB libraries):

```bash
cargo install --path . --no-default-features
```

## Setup

On the **server**, print its id:

```bash
fidroh id
```

On the **laptop**, with your security key plugged in:

```bash
fidroh register          # PIN + one touch; prints a fidroh1:… token
```

Carry the token to the **server's console** (it contains only public data) and enroll it:

```bash
fidroh enroll my-laptop fidroh1:…
```

## Daily use

Server (leave it running; your app listens on 127.0.0.1:4000):

```bash
fidroh serve --upstream 127.0.0.1:4000
```

Laptop:

```bash
fidroh connect <server-id>   # PIN + one touch
# then browse to http://127.0.0.1:8443
```

## Files

Each machine keeps its state in a data folder: `~/.local/share/fidroh` by default, or set with `-d` / `FIDROH_DATA_DIR`.

| File | What | Secret? |
| --- | --- | --- |
| `secret.key` | this machine's identity (mode 0600) | **yes**; never share or commit it |
| `fidroh.db` | server only: enrolled laptops, credentials, audit log | public data, but guard it from tampering |

Enrollment tokens and endpoint ids are public and safe to paste anywhere.

## Logging

```bash
RUST_LOG=fidroh=debug fidroh serve …           # per-stream detail
RUST_LOG=fidroh=debug,iroh=info fidroh serve …  # plus iroh networking
```

## WSL2 notes (laptop side)

The security key must be passed through from Windows with [usbipd-win](https://github.com/dorssel/usbipd-win): `usbipd bind` once, then `usbipd attach --wsl --hardware-id 1050:0407` per session, and give your user access to its `/dev/hidraw*` device.

## Roadmap

- `fidroh devices` / `fidroh remove` (today: delete from `fidroh.db` by hand)
- Multiple named routes per server (e.g. `web`, `db`)
- End the session when the security key is unplugged
- Native Windows client via the Windows WebAuthn API

## License

MIT OR Apache-2.0