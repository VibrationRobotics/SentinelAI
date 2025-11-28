//! SentinelAI Desktop - Tauri Backend v1.4.0
//! Embeds the Python agent and provides native Windows GUI
//! Features: Hybrid ML detection, AI analysis, auto-start, system tray

use std::process::{Command, Child};
use std::sync::Mutex;
use std::path::PathBuf;
use tauri_plugin_autostart::MacosLauncher;

// Global agent process handle
static AGENT_PROCESS: Mutex<Option<Child>> = Mutex::new(None);

// Configuration - Change this for SaaS deployment
// Local: http://localhost:8015
// External: http://148.170.66.162:8015 or https://sentinel.vibrationrobotics.com
const DEFAULT_DASHBOARD_URL: &str = "http://localhost:8015";

/// Get the path to the embedded Python agent
fn get_agent_path() -> (PathBuf, bool) {
    // Check multiple locations
    let possible_paths = vec![
        // Same directory as exe
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("agent.py")))
            .unwrap_or_else(|| PathBuf::from("agent.py")),
        // Sentinel desktop folder
        PathBuf::from(r"F:\DESKTOP\sentinel\SentinelAI\sentinel-desktop\agent.py"),
        // Windows agent folder (original)
        PathBuf::from(r"F:\DESKTOP\sentinel\SentinelAI\windows_agent\agent.py"),
    ];
    
    for path in possible_paths {
        if path.exists() {
            return (path, true);
        }
    }
    
    (PathBuf::from(r"F:\DESKTOP\sentinel\SentinelAI\windows_agent\agent.py"), false)
}

/// Start the Python agent in the background
#[tauri::command]
async fn start_agent(dashboard_url: Option<String>) -> Result<String, String> {
    let mut process_guard = AGENT_PROCESS.lock().map_err(|e| e.to_string())?;
    
    // Check if already running
    if let Some(ref mut child) = *process_guard {
        match child.try_wait() {
            Ok(Some(_)) => {
                // Process has exited, we can start a new one
                *process_guard = None;
            }
            Ok(None) => {
                return Ok("Agent already running".to_string());
            }
            Err(_) => {
                *process_guard = None;
            }
        }
    }
    
    let (agent_path, exists) = get_agent_path();
    if !exists {
        return Err(format!("Agent not found at: {:?}", agent_path));
    }
    
    let url = dashboard_url.unwrap_or_else(|| DEFAULT_DASHBOARD_URL.to_string());
    
    // Get the agent directory for working directory
    let agent_dir = agent_path.parent().unwrap_or(&agent_path).to_path_buf();
    
    // Find Python executable
    let python_paths = vec![
        PathBuf::from(r"C:\Users\markv\AppData\Local\Programs\Python\Python311\python.exe"),
        PathBuf::from("python"),
        PathBuf::from("python3"),
    ];
    
    let python_exe = python_paths.iter()
        .find(|p| p.exists() || p.to_str() == Some("python") || p.to_str() == Some("python3"))
        .cloned()
        .unwrap_or_else(|| PathBuf::from("python"));
    
    // Start Python agent with proper working directory
    let child = Command::new(&python_exe)
        .arg(&agent_path)
        .arg("--dashboard")
        .arg(&url)
        .current_dir(&agent_dir)
        .spawn()
        .map_err(|e| format!("Failed to start: {}. Python: {:?}, Agent: {:?}, Dir: {:?}", e, python_exe, agent_path, agent_dir))?;
    
    let pid = child.id();
    *process_guard = Some(child);
    Ok(format!("Agent started (PID: {}), connecting to {}", pid, url))
}

/// Stop the Python agent
#[tauri::command]
async fn stop_agent() -> Result<String, String> {
    let mut process_guard = AGENT_PROCESS.lock().map_err(|e| e.to_string())?;
    
    if let Some(ref mut child) = *process_guard {
        child.kill().map_err(|e| format!("Failed to stop agent: {}", e))?;
        *process_guard = None;
        Ok("Agent stopped".to_string())
    } else {
        Ok("Agent was not running".to_string())
    }
}

/// Check if agent is running
#[tauri::command]
async fn is_agent_running() -> Result<bool, String> {
    let mut process_guard = AGENT_PROCESS.lock().map_err(|e| e.to_string())?;
    
    if let Some(ref mut child) = *process_guard {
        match child.try_wait() {
            Ok(Some(_)) => {
                *process_guard = None;
                Ok(false)
            }
            Ok(None) => Ok(true),
            Err(_) => Ok(false)
        }
    } else {
        Ok(false)
    }
}

/// Get agent status from dashboard API
#[tauri::command]
async fn get_agent_status() -> Result<String, String> {
    // Try to fetch from dashboard
    let client = reqwest::Client::new();
    match client.get(format!("{}/api/v1/windows/agent/list", DEFAULT_DASHBOARD_URL))
        .timeout(std::time::Duration::from_secs(3))
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                response.text().await.map_err(|e| e.to_string())
            } else {
                Err(format!("Dashboard returned: {}", response.status()))
            }
        }
        Err(e) => Err(format!("Cannot reach dashboard: {}", e))
    }
}

/// Block an IP address via the dashboard API
#[tauri::command]
async fn block_ip(ip: String) -> Result<String, String> {
    let client = reqwest::Client::new();
    match client.post(format!("{}/api/v1/windows/firewall/block/{}", DEFAULT_DASHBOARD_URL, ip))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                Ok(format!("Blocked IP: {}", ip))
            } else {
                Err(format!("Failed to block: {}", response.status()))
            }
        }
        Err(e) => Err(format!("Request failed: {}", e))
    }
}

/// Get dashboard URL
#[tauri::command]
fn get_dashboard_url() -> String {
    DEFAULT_DASHBOARD_URL.to_string()
}

/// Get security events from dashboard
#[tauri::command]
async fn get_security_events(limit: Option<u32>) -> Result<String, String> {
    let client = reqwest::Client::new();
    let limit = limit.unwrap_or(50);
    match client.get(format!("{}/api/v1/windows/events?limit={}", DEFAULT_DASHBOARD_URL, limit))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                response.text().await.map_err(|e| e.to_string())
            } else {
                Err(format!("Dashboard returned: {}", response.status()))
            }
        }
        Err(e) => Err(format!("Cannot reach dashboard: {}", e))
    }
}

/// Get recent threats from dashboard
#[tauri::command]
async fn get_recent_threats() -> Result<String, String> {
    let client = reqwest::Client::new();
    match client.get(format!("{}/api/v1/threats/recent", DEFAULT_DASHBOARD_URL))
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(response) => {
            if response.status().is_success() {
                response.text().await.map_err(|e| e.to_string())
            } else {
                Err(format!("Dashboard returned: {}", response.status()))
            }
        }
        Err(e) => Err(format!("Cannot reach dashboard: {}", e))
    }
}

/// Toggle autostart on boot
#[tauri::command]
async fn set_autostart(app: tauri::AppHandle, enabled: bool) -> Result<String, String> {
    use tauri_plugin_autostart::ManagerExt;
    let autostart_manager = app.autolaunch();
    
    if enabled {
        autostart_manager.enable().map_err(|e| e.to_string())?;
        Ok("Autostart enabled".to_string())
    } else {
        autostart_manager.disable().map_err(|e| e.to_string())?;
        Ok("Autostart disabled".to_string())
    }
}

/// Check if autostart is enabled
#[tauri::command]
async fn is_autostart_enabled(app: tauri::AppHandle) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    let autostart_manager = app.autolaunch();
    autostart_manager.is_enabled().map_err(|e| e.to_string())
}

/// Minimize window
#[tauri::command]
async fn minimize_window(window: tauri::Window) -> Result<(), String> {
    window.minimize().map_err(|e| e.to_string())
}

/// Maximize/restore window
#[tauri::command]
async fn toggle_maximize(window: tauri::Window) -> Result<(), String> {
    if window.is_maximized().unwrap_or(false) {
        window.unmaximize().map_err(|e| e.to_string())
    } else {
        window.maximize().map_err(|e| e.to_string())
    }
}

/// Close window and stop agent
#[tauri::command]
async fn close_window(window: tauri::Window) -> Result<(), String> {
    // Stop agent first
    let _ = stop_agent().await;
    window.close().map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_autostart::init(MacosLauncher::LaunchAgent, Some(vec!["--minimized"])))
        .setup(|_app| {
            // Agent will be started via frontend on load
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_agent,
            stop_agent,
            is_agent_running,
            get_agent_status,
            get_security_events,
            get_recent_threats,
            block_ip,
            get_dashboard_url,
            set_autostart,
            is_autostart_enabled,
            minimize_window,
            toggle_maximize,
            close_window
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
