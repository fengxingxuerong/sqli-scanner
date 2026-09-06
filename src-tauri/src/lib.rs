// SQL 注入检测工具桌面壳（Tauri v2）
// 职责：启动本地 Node 检测引擎（sidecar，监听 127.0.0.1:4567）+ 加载前端窗口
// P0-7：应用退出时 kill sidecar，避免僵尸进程；初始化 dialog/fs 插件供前端使用

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

// [打包修复] Tauri v2 把 emit 移入 `Emitter` trait，必须显式导入（v1 在 AppHandle 固有方法上）
use tauri::{Emitter, Manager};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

// 子进程句柄（用于停止 sidecar）
struct EngineChild(std::sync::Mutex<Option<CommandChild>>);

// 启动/重启本地 Node 检测引擎（sidecar）
// 可重入：重启时先 kill 残留旧进程，再写入新句柄（不二次 manage 覆盖丢句柄）
fn spawn_engine(app: &tauri::AppHandle) {
    let sidecar = app
        .shell()
        .sidecar("sqli-engine")
        .expect("找不到 sidecar 引擎可执行文件，请先执行 npm run build:engine 并放入 src-tauri/binaries/");

    let (mut rx, child) = sidecar.spawn().expect("启动 sidecar 引擎失败");

    // 复用 run() 时注册的 EngineChild state：先 kill 残留旧进程，再写入新句柄
    if let Some(state) = app.try_state::<EngineChild>() {
        if let Ok(mut guard) = state.0.lock() {
            if let Some(old) = guard.take() {
                let _ = old.kill(); // 清理可能残留的旧进程
            }
            *guard = Some(child);
        }
    }

    // [打包修复] spawn 闭包需 'static：先 clone AppHandle，避免借用逃逸（E0521）
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stderr(line) => {
                    println!("[引擎] {}", String::from_utf8_lossy(&line));
                }
                // 引擎进程退出：向前端广播（前端 Snackbar 提示 + 重启按钮）
                CommandEvent::Terminated(payload) => {
                    println!("[引擎] 进程退出 code={:?}", payload.code);
                    let _ = app_handle.emit(
                        "engine-exit",
                        serde_json::json!({
                            "code": payload.code,
                            "signal": payload.signal.map(|s| s.to_string()),
                        }),
                    );
                }
                _ => {}
            }
        }
    });
}

// 供前端调用的「启动引擎」命令（桌面版：真正重新拉起 sidecar）
#[tauri::command]
fn start_engine(app: tauri::AppHandle) -> Result<String, String> {
    spawn_engine(&app);
    Ok("引擎已重新拉起".to_string())
}

// 供前端调用的「停止引擎」命令
#[tauri::command]
fn stop_engine(app: tauri::AppHandle) -> Result<String, String> {
    if let Some(state) = app.try_state::<EngineChild>() {
        if let Ok(mut guard) = state.0.lock() {
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
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(EngineChild(std::sync::Mutex::new(None)))
        .setup(|app| {
            // 应用启动时拉起本地检测引擎
            spawn_engine(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![start_engine, stop_engine])
        .build(tauri::generate_context!())
        .expect("构建 Tauri 应用失败");

    // P0-7：应用退出时确保 sidecar 进程被 kill，避免僵尸进程
    app.run(|app_handle, event| {
        if let tauri::RunEvent::Exit = event {
            if let Some(state) = app_handle.try_state::<EngineChild>() {
                if let Ok(mut guard) = state.0.lock() {
                    if let Some(child) = guard.take() {
                        let _ = child.kill();
                    }
                }
            }
        }
    });
}
