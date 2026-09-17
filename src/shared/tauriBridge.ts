// Tauri 桥接：Web 版为 no-op；Tauri 版通过 @tauri-apps/api 与系统交互。
// 业务组件不感知差异，统一经本模块调用引擎启停与文件保存。

let tauriAvailable = false;
try {
  // 仅在 Tauri 运行时（window 挂载 __TAURI_INTERNALS__）置为可用
  tauriAvailable =
    typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
} catch {
  tauriAvailable = false;
}

export const tauriBridge = {
  isTauri: tauriAvailable,

  // 监听引擎退出事件（Tauri 桌面版：Rust 侧 emit('engine-exit')）
  // Web 版为 no-op；Tauri 版注册监听器返回取消函数
  onEngineExit(callback: (payload: { code: number | null; signal: string | null }) => void): (() => void) | null {
    if (!tauriAvailable) return null;
    let unlisten: (() => void) | null = null;
    import('@tauri-apps/api/event')
      .then(({ listen }) => listen<{ code: number | null; signal: string | null }>('engine-exit', (event) => {
        callback(event.payload);
      }))
      .then((fn) => { unlisten = fn; })
      .catch(() => undefined);
    return () => { if (unlisten) unlisten(); };
  },

  // [A3 2026-09-17] 读取 Rust 侧 sidecar 的实连信息：{ port, token }
  // 桌面版引擎不再固定 4567（被占则用随机端口），且带一次性 token，
  // 前端必须向 Rust 询问后才能正确连接（Web 版返回 null，走同源 /api）。
  async getEngineInfo(): Promise<{ port: number; token: string } | null> {
    if (!tauriAvailable) return null;
    try {
      const { invoke } = await import('@tauri-apps/api/core');
      const info = await (invoke as any)('get_engine_info');
      if (info && typeof info.port === 'number') {
        return { port: info.port, token: String(info.token || '') };
      }
    } catch { /* 命令不存在（旧壳）或引擎未起 → 降级为默认端口 */ }
    return null;
  },

  // 启动本地引擎（Tauri 由 Rust 侧 sidecar 自动拉起；Web 版无需操作）
  async startEngine(): Promise<void> {
    if (!tauriAvailable) return;
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('start_engine').catch(() => undefined);
  },

  // 停止本地引擎
  async stopEngine(): Promise<void> {
    if (!tauriAvailable) return;
    const { invoke } = await import('@tauri-apps/api/core');
    await invoke('stop_engine').catch(() => undefined);
  },

  // 保存文件（导出报告）。Web 版用浏览器下载；Tauri 版用 dialog 选择路径落盘
  async saveFile(name: string, content: string, mime: string): Promise<void> {
    if (!tauriAvailable) {
      const blob = new Blob([content], { type: mime });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = name;
      a.click();
      URL.revokeObjectURL(a.href);
      return;
    }
    // 桌面版：选择路径并写入
    // 使用变量形式的动态导入，避免 Web 构建时解析未安装的 Tauri 插件模块
    const dialogSpec = '@tauri-apps/plugin-dialog';
    const dialog = await import(dialogSpec);
    const path = await (dialog as any).save({ defaultPath: name });
    if (path) {
      const fsSpec = '@tauri-apps/plugin-fs';
      const fs = await import(fsSpec);
      await (fs as any).writeTextFile(path, content);
    }
  },

  // 打开文本文件（对标 sqlmap -r 的请求文件导入）。
  // Web 版：隐藏 <input type=file> + FileReader；Tauri 版：dialog 选择 + fs 读取。
  // 返回文件文本内容；用户取消或无文件返回 null。
  async openTextFile(accept = '.txt,.req,.http'): Promise<string | null> {
    if (!tauriAvailable) {
      return await new Promise((resolve) => {
        const input = document.createElement('input');
        input.type = 'file';
        input.accept = accept;
        input.onchange = () => {
          const file = input.files && input.files[0];
          if (!file) return resolve(null);
          const reader = new FileReader();
          reader.onload = () => resolve(typeof reader.result === 'string' ? reader.result : null);
          reader.onerror = () => resolve(null);
          reader.readAsText(file);
        };
        input.click();
      });
    }
    // 桌面版：dialog 选文件 + fs 读文本
    const dialogSpec = '@tauri-apps/plugin-dialog';
    const dialog = await import(dialogSpec);
    const path = await (dialog as any).open({
      multiple: false,
      filters: [{ name: 'HTTP Request', extensions: ['txt', 'req', 'http'] }],
    });
    if (typeof path !== 'string') return null;
    const fsSpec = '@tauri-apps/plugin-fs';
    const fs = await import(fsSpec);
    return await (fs as any).readTextFile(path);
  },
};

export default tauriBridge;
