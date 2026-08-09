// SQL 注入检测工具桌面壳（Tauri v2）
// 职责：启动本地 Node 检测引擎（sidecar，监听 127.0.0.1:4567）+ 加载前端窗口

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

// 子进程句柄（用于停止 sidecar）
struct EngineChild(std::sync::Mutex<Option<CommandChild>>);

// 启动本地 Node 检测引擎（sidecar）
fn spawn_engine(app: &tauri::AppHandle) {
    let sidecar = app
        .shell()
        .sidecar("sqli-engine")
        .expect("找不到 sidecar 引擎可执行文件，请先执行 npm run build:engine 并放入 src-tauri/binaries/");

    let (mut rx, child) = sidecar.spawn().expect("启动 sidecar 引擎失败");
    app.manage(EngineChild(std::sync::Mutex::new(Some(child))));

    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            if let CommandEvent::Stderr(line) = event {
                println!("[引擎] {}", String::from_utf8_lossy(&line));
            }
        }
    });
}

// 供前端调用的「启动引擎」命令（桌面版；Web 版为 no-op）
#[tauri::command]
fn start_engine() -> Result<String, String> {
    Ok("引擎已由 sidecar 自动拉起".to_string())
}

// 供前端调用的「停止引擎」命令
#[tauri::command]
fn stop_engine(app: tauri::AppHandle) -> Result<String, String> {
    if let Some(state) = app.try_state::<EngineChild>() {
        if let Some(mut guard) = state.0.lock().ok().as_mut() {
            if let Some(child) = guard.take() {
                let _ = child.kill();
                return Ok("已停止引擎".to_string());
            }
        }
    }
    Ok("引擎未在运行".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(EngineChild(std::sync::Mutex::new(None)))
        .setup(|app| {
            // 应用启动时拉起本地检测引擎
            spawn_engine(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![start_engine, stop_engine])
        .run(tauri::generate_context!())
        .expect("运行 Tauri 应用失败");
}
