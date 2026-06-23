# VcfPatchScanner Release Notes

## 1.0.0.1001

### What's new

**Module update notifications.** The web UI now checks PowerShell Gallery at startup for a newer version
of VcfPatchScanner. When a newer version is detected, a dismissible banner appears with three options:
install automatically (runs `Update-Module` in a background PowerShell subprocess), show manual
installation instructions, or dismiss until the next session. If PSGallery is unreachable — for example
due to firewall restrictions — a separate amber warning is shown with a one-click option to disable
future checks. Module update checks can also be permanently disabled in Advanced Settings, independently
of the advisory database update check.

---

## 1.0.0.1000 — Initial Release

### Summary

VcfPatchScanner is a PowerShell module that scans VMware Cloud Foundation environments for
security vulnerabilities and produces structured patch-guidance reports. It connects directly
to SDDC Manager, VCF Operations, and the Fleet Manager API to collect live inventory, then
matches component versions against the Broadcom security advisory database.
