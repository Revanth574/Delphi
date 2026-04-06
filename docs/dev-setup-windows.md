# Delphi OS — Windows Development Setup Guide

This guide sets up a full Delphi OS development environment on Windows 11 using WSL2 for Linux-specific builds (Wayland compositor, D-Bus IPC, system integration).

## Architecture

```
Windows 11 Host
├── Claude Code / VS Code — editor (Windows-native)
├── shell/ — React 19 UI (runs natively on Windows via Vite dev server)
└── WSL2 (Ubuntu 24.04)
    ├── Rust workspace — full compilation including compositor
    ├── Smithay — Wayland compositor (needs libwayland)
    ├── D-Bus — IPC (needs libdbus)
    └── llama.cpp — local inference (needs cmake + CUDA/Vulkan)
```

**What runs on Windows natively:** TypeScript/React shell, Rust crates without Linux deps (fortress, die-inference, semantic-fs, die-orchestrator, ssi).

**What requires WSL2:** Compositor (Smithay/Wayland), full workspace builds, D-Bus runtime, GPU inference.

---

## Step 1: Install WSL2

Open **PowerShell as Administrator** and run:

```powershell
wsl --install -d Ubuntu-24.04
```

This installs:
- WSL2 kernel
- Ubuntu 24.04 LTS
- WSLg (Wayland/X11 GUI support — included in Windows 11)

**Reboot when prompted.** After reboot, Ubuntu will open and ask you to create a username and password.

### Verify WSL2 is working

```powershell
# In PowerShell
wsl --version
wsl -l -v
```

You should see Ubuntu-24.04 with VERSION 2.

---

## Step 2: Enable systemd in WSL2

Systemd is required for D-Bus and other system services. Inside WSL2:

```bash
sudo tee /etc/wsl.conf > /dev/null << 'EOF'
[boot]
systemd=true

[interop]
enabled=true
appendWindowsPath=true
EOF
```

Then restart WSL2 from PowerShell:

```powershell
wsl --shutdown
wsl
```

Verify systemd is running:

```bash
systemctl --version
```

---

## Step 3: Run the Delphi setup script

The setup script installs all development dependencies:

```bash
# Navigate to the Delphi workspace (accessible from WSL2 via /mnt/c/)
cd /mnt/c/Users/YOUR_USERNAME/OneDrive/Desktop/Delphi

# Make the script executable and run it
chmod +x scripts/setup-wsl2.sh
./scripts/setup-wsl2.sh
```

The script installs:

| Category | Packages |
|----------|----------|
| Build tools | build-essential, pkg-config, cmake, libssl-dev |
| Wayland | libwayland-dev, libxkbcommon-dev, libudev-dev, libinput-dev, libgbm-dev, libseat-dev |
| GPU | libvulkan-dev, mesa-vulkan-drivers, libglfw3-dev, libegl-dev |
| Rust | rustup (stable toolchain, edition 2024 support) |
| Node.js | v22 LTS + pnpm |
| Python | 3.12+ with pip |
| llama.cpp | cmake, libcurl4-openssl-dev |
| IPC | protobuf-compiler, libdbus-1-dev |
| Containers | flatpak, podman |

---

## Step 4: Verify the workspace compiles

```bash
cd /mnt/c/Users/YOUR_USERNAME/OneDrive/Desktop/Delphi

# Full workspace including compositor (should work now!)
cargo check --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings

# Shell UI
cd shell && pnpm install && pnpm test && pnpm build
```

---

## WSLg — GUI apps in WSL2

Windows 11 includes WSLg, which provides a Wayland compositor inside WSL2. This means you can run graphical apps (including the Delphi compositor in development mode) directly from WSL2 and they appear as Windows windows.

To verify WSLg is working:

```bash
# Install a simple GUI app
sudo apt-get install -y x11-apps
xclock  # Should open a clock window on your Windows desktop
```

If the clock appears, WSLg is working and the compositor will be able to render.

---

## GPU Passthrough for Inference

For local LLM inference (Tier 1/2), you need GPU access in WSL2:

### NVIDIA GPU
1. Install the **NVIDIA GPU driver** on Windows (NOT inside WSL2)
2. The CUDA toolkit is automatically available in WSL2 via the driver
3. Verify: `nvidia-smi` inside WSL2 should show your GPU

### AMD GPU
1. Install the latest AMD driver on Windows
2. Verify Vulkan: `vulkaninfo | head -20` inside WSL2

### Intel iGPU / NPU
1. Intel NPU support in WSL2 is experimental
2. For iGPU: install Intel GPU drivers on Windows, verify with `vainfo`

---

## Troubleshooting

### "WSL2 requires an update to its kernel component"
```powershell
wsl --update
```

### Slow filesystem access on /mnt/c/
The Windows filesystem is slow from WSL2. For build performance, clone the repo inside WSL2's native filesystem:

```bash
# Inside WSL2
cd ~
git clone /mnt/c/Users/YOUR_USERNAME/OneDrive/Desktop/Delphi
cd Delphi
cargo check --workspace  # Much faster builds
```

### "cannot find -lwayland-client"
The Wayland dev libraries are missing. Re-run the setup script or:
```bash
sudo apt-get install -y libwayland-dev
```

### Compositor crashes immediately
Check that WSLg is working (`xclock` test above). If not:
```powershell
# In PowerShell
wsl --shutdown
wsl --update
wsl
```

---

## Editor Integration

### VS Code with WSL2
1. Install the **WSL** extension in VS Code
2. Open the project: `code .` from inside WSL2
3. VS Code runs its backend inside WSL2 with full access to Linux toolchains

### Claude Code
Claude Code works directly on Windows. The Rust crates that don't need Linux (fortress, inference, semantic-fs, orchestrator, ssi) compile natively on Windows with MSVC.

For full workspace builds, use Claude Code inside a WSL2 terminal.
