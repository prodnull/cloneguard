# CloneGuard MDM Fleet Deployment

Deploy CloneGuard to macOS managed fleets via Jamf Pro or Microsoft Intune.

## Profile Overview

| Profile | Purpose |
|---------|---------|
| `cloneguard-install.mobileconfig` | Installs CloneGuard with `[mini]` extras, initializes global hooks, creates `~/.cloneguard/` |
| `cloneguard-policy.mobileconfig` | Deploys `policy.yaml` with safe defaults (dry_run=true, standard thresholds) |

Each profile is available in platform-specific directories:
- `jamf/` -- PayloadIdentifier prefix `com.cloneguard.*`
- `intune/` -- PayloadIdentifier prefix `com.microsoft.intune.cloneguard.*`

## Prerequisites

- macOS 10.15 (Catalina) or later
- One of: `uv`, `pipx`, or `pip3` installed on target machines
- Python 3.11+ runtime
- MDM enrollment (Jamf Pro or Microsoft Intune)

## Signing

These profiles are shipped **unsigned** as templates. You **must** sign them
with your organization's certificate before deploying via MDM. Unsigned
profiles trigger visible warnings on target devices and may be rejected by
MDM platforms.

Sign a profile:

```bash
security cms -S -N 'Your Org Certificate Name' \
  -i cloneguard-install.mobileconfig \
  -o signed-cloneguard-install.mobileconfig
```

To list available signing identities:

```bash
security find-identity -v -p codesigning
```

## Jamf Pro Deployment

1. **Customize** the `.mobileconfig` files (version, thresholds, extras) as needed
2. **Sign** each profile with your organization certificate
3. **Upload** to Jamf Pro: Computers > Configuration Profiles > Upload
4. **Scope** to target Smart Groups or individual machines
5. **Deploy** -- profiles install automatically at next MDM check-in

### Recommended deployment order

1. Deploy `cloneguard-install.mobileconfig` first (installs the tool)
2. Deploy `cloneguard-policy.mobileconfig` second (configures policy)

## Intune Deployment

1. **Customize** the `.mobileconfig` files as needed
2. **Sign** each profile with your organization certificate
3. **Upload** to Intune: Devices > macOS > Configuration profiles > Create > Templates > Custom
4. **Assign** to device groups
5. **Deploy** -- profiles install automatically at next Intune sync

## Customization

Before signing, edit the profile XML to adjust:

### Version pinning

In the install script, change `cloneguard` to `cloneguard==X.Y.Z`:

```bash
uv tool install cloneguard==1.0.0 --with 'cloneguard[mini]'
```

### Detection thresholds

In `cloneguard-policy.mobileconfig`, modify the embedded `policy.yaml`:

```yaml
verdicts:
  thresholds:
    suspicious_floor: 0.25   # Lower = more sensitive
    malicious_floor: 0.65    # Lower = more aggressive blocking
```

### Extra packages

In the install script, modify the extras list:

```bash
uv tool install cloneguard --with 'cloneguard[mini,opa,cedar]'
```

### Disabling dry-run

In `cloneguard-policy.mobileconfig`, change `dry_run: true` to
`dry_run: false` **only after** validating thresholds on a test group.

## Verification

After deployment, verify on target machines:

```bash
# Check installation
cloneguard --version

# Check hook configuration
cat ~/.claude/settings.json

# Check policy
cat ~/.cloneguard/policy.yaml

# Run a test scan
cloneguard scan .
```

## Troubleshooting

### "Profile is not signed" warning

Sign the profile before deploying. See the Signing section above.

### "No Python package installer found"

Ensure `uv`, `pipx`, or `pip3` is installed on target machines before
deploying the install profile. Use a prerequisite profile or script to
install `uv` via `curl -LsSf https://astral.sh/uv/install.sh | sh`.

### Permission denied on ~/.cloneguard

The install script creates `~/.cloneguard` with mode `0700`. If the
directory was previously created by another user or with wrong permissions:

```bash
chmod 0700 ~/.cloneguard
chown $(whoami) ~/.cloneguard
```

### Hooks not firing in Claude Code

Verify the settings file exists and contains the hook configuration:

```bash
cat ~/.claude/settings.json
```

If missing, re-run: `cloneguard init --global`

### Profile conflicts

If both Jamf and Intune manage the same device, use only one set of profiles.
The different PayloadIdentifier prefixes prevent silent overwrites but may
cause conflicting policy deployments.
