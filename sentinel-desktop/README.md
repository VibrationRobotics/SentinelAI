# SentinelAI Desktop

Native Windows desktop application for SentinelAI with system tray support.

## Features

- 🛡️ **Native Windows GUI** - Beautiful dark-themed interface
- 📊 **Real-time Monitoring** - See threats and events as they happen
- 🔔 **System Tray** - Runs in background with notifications
- ⚡ **Quick Actions** - One-click threat response
- 🔗 **Dashboard Integration** - Opens web dashboard for detailed analysis

## Prerequisites

- Node.js 18+
- Rust (via rustup)
- Windows 10/11

## Development

```bash
# Install dependencies
npm install

# Run in development mode
npm run tauri dev

# Build for production
npm run tauri build
```

## Building

The build will create:
- `SentinelAI Desktop.exe` - Standalone executable
- `SentinelAI Desktop.msi` - Windows installer

## Architecture

```
sentinel-desktop/
├── index.html          # Main UI
├── src/
│   └── main.js         # Frontend JavaScript
├── src-tauri/
│   ├── src/
│   │   ├── main.rs     # Tauri entry point
│   │   └── lib.rs      # Rust backend logic
│   ├── Cargo.toml      # Rust dependencies
│   └── tauri.conf.json # Tauri configuration
└── package.json        # Node dependencies
```

## Integration

The desktop app connects to:
- **Dashboard API** (localhost:8015) - For threat data and agent status
- **Python Agent** - Can start/stop the Windows agent

## System Tray Menu

- **Show Window** - Bring app to foreground
- **Open Dashboard** - Open web dashboard in browser
- **Quit** - Exit application completely

## Notes

- Closing the window minimizes to tray (background protection)
- Requires the Docker dashboard to be running for full functionality
- Can run alongside the Python agent or manage it directly
