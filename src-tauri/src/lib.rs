// SQL 注入检测工具桌面壳（Tauri v2）
// 职责：启动本地 Node 检测引擎（sidecar，监听 127.0.0.1:4567）+ 加载前端窗口
// P0-7：应用退出时 kill sidecar，避免僵尸进程；初始化 dialog/fs 插件供前端使用

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::TcpListener;
use std::time::Duration;

// [打包修复] Tauri v2 把 emit 移入 `Emitter` trait，必须显式导入（v1 在 AppHandle 固有方法上）
use tauri::{Emitter, Manager};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

// 子进程句柄（用于停止 sidecar）
struct EngineChild(std::sync::Mutex<Option<CommandChild>>);

// [A3 2026-09-17] 引擎实连信息：(监听端口, 一次性 token)
// 旧实现把端口写死 4567 且无鉴权：本机任何进程都能连上这个「能扫能拖库」的引擎，
// 甚至可以先占 4567 冒充引擎（WebView 的 CSP 允许该 origin）截获目标 Cookie 与拖库结果。
// 现在：端口被占则换空闲端口；token 由引擎（Node crypto）生成后经 stdout 回传，壳再转交前端。
struct EngineInfo(std::sync::Mutex<(u16, String)>);

/// 选择引擎监听端口：优先 4567（便于人工排查），被占用则退回系统分配的空闲端口。
/// 说明：bind→drop 之间存在极短的 TOCTOU 窗口，命中时 sidecar 会启动失败，
/// 由前端「重启引擎」按钮重试（比让整个应用 panic 可控）。
fn pick_engine_port() -> u16 {
    if TcpListener::bind("127.0.0.1:4567").is_ok() {
        return 4567;
    }
    match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l.local_addr().map(|a| a.port()).unwrap_or(4567),
        Err(_) => 4567,
    }
}

// 启动/重启本地 Node 检测引擎（sidecar）
// 可重入：重启时先 kill 残留旧进程，再写入新句柄（不二次 manage 覆盖丢句柄）
// [A3] 全路径免 panic：构造/spawn 失败只广播 engine-exit，由前端提供重试入口。
fn spawn_engine(app: &tauri::AppHandle) {
    let port = pick_engine_port();

    let cmd = match app.shell().sidecar("sqli-engine") {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[引擎] 构造 sidecar 失败：{}", e);
            let _ = app.emit(
                "engine-exit",
                serde_json::json!({ "code": null, "signal": null, "error": format!("{}", e) }),
            );
            return;
        }
    };

    // 注入引擎配置：端口 / 回环监听 / 一次性 token / 允许 Tauri WebView 的 origin
    let cmd = cmd
        .env("HOST", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("SCAN_API_TOKEN_EMIT", "1")
        .env(
            "ALLOWED_ORIGINS",
            "http://tauri.localhost,tauri://localhost",
        );

    let (mut rx, child) = match cmd.spawn() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[引擎] 启动 sidecar 失败：{}", e);
            let _ = app.emit(
                "engine-exit",
                serde_json::json!({ "code": null, "signal": null, "error": format!("{}", e) }),
            );
            return;
        }
    };

    // 复用 run() 时注册的 EngineChild state：先 kill 残留旧进程，再写入新句柄
    if let Some(state) = app.try_state::<EngineChild>() {
        if let Ok(mut guard) = state.0.lock() {
            if let Some(old) = guard.take() {
                let _ = old.kill(); // 清理可能残留的旧进程
            }
            *guard = Some(child);
        }
    }

    // 捕获引擎 stdout 的 ENGINE_TOKEN=<hex>（一次性 token），超时则降级为空串
    let (tx, token_rx) = std::sync::mpsc::channel::<String>();

    // [打包修复] spawn 闭包需 'static：先 clone AppHandle，避免借用逃逸（E0521）
    let app_handle = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(event) = rx.recv().await {
            match event {
                CommandEvent::Stdout(line) => {
                    let text = String::from_utf8_lossy(&line);
                    // 同一块输出可能含多行（日志与 token 混排）→ 逐行匹配更稳
                    for l in text.lines() {
                        if let Some(rest) = l.trim().strip_prefix("ENGINE_TOKEN=") {
                            let _ = tx.send(rest.trim().to_string());
                        }
                    }
                }
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

    let token = token_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| {
            eprintln!("[引擎] 未在 5 秒内收到 ENGINE_TOKEN，将以无 token 方式继续（前端可能 401）");
            String::new()
        });

    if let Some(state) = app.try_state::<EngineInfo>() {
        if let Ok(mut guard) = state.0.lock() {
            *guard = (port, token);
        }
    }
    println!("[引擎] sidecar 已启动：127.0.0.1:{}", port);
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

// [A3 2026-09-17] 前端启动后先问一次实连信息：端口（可能非 4567）+ 一次性 token。
// 未拿到 port（0）表示引擎未就绪，前端保持默认 base 不动。
#[tauri::command]
fn get_engine_info(app: tauri::AppHandle) -> Result<serde_json::Value, String> {
    let (port, token) = match app.try_state::<EngineInfo>() {
        Some(state) => match state.0.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => (0u16, String::new()),
        },
        None => (0u16, String::new()),
    };
    Ok(serde_json::json!({ "port": port, "token": token }))
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_fs::init())
        .manage(EngineChild(std::sync::Mutex::new(None)))
        .manage(EngineInfo(std::sync::Mutex::new((0u16, String::new()))))
        .setup(|app| {
            // 应用启动时拉起本地检测引擎
            spawn_engine(app.handle());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            start_engine,
            stop_engine,
            get_engine_info
        ])
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
