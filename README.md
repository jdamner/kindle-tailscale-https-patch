# KOReader Tailscale HTTPS CONNECT patch

This KOReader user patch allows LuaSec HTTPS requests to use the HTTP CONNECT
proxy exposed by Tailscale userspace networking.

It is intended for Kindle installations using the KOReader Tailscale plugin,
where the proxy is normally available at `127.0.0.1:1056`. This is useful for
plugins such as CWNG Sync that need to reach an HTTPS service over a tailnet.

## Install

Copy `2-tailscale-https-connect.lua` to:

```text
/mnt/us/koreader/patches/2-tailscale-https-connect.lua
```

Keep KOReader's original `common/ssl/https.lua` unchanged. Restart KOReader
after installing the patch.

The patch enables the Tailscale HTTP proxy when the Tailscale plugin loads.
It applies the HTTPS transport patch when the `cwngsync` plugin loads.

## Scope and limitations

- Designed for KOReader's Tailscale userspace mode and its HTTP CONNECT proxy.
- It does not provide system-wide routing.
- TLS certificate verification follows KOReader's existing LuaSec behavior.
- Remove or rename the patch file to disable it.

## Attribution and license

The patch adapts KOReader's LuaSec/LuaSocket HTTPS transport for HTTP CONNECT
proxying. KOReader is licensed under the GNU Affero General Public License,
version 3 or later; see [`LICENSE`](LICENSE).
