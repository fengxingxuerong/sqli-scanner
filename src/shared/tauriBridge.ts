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
      // invoke 的默认返回类型是 {} —— 原先靠 `as any` 抹平，改成显式泛型：
      // Rust 侧 get_engine_info 的返回形态在这里被写进类型，改壳不改这里就会编译不过。
      const info = await invoke<{ port?: number; token?: string } | null>('get_engine_info');
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
    // ⚠️ 这里必须用**字面量**动态导入：以前写成变量形式（`const spec = '@tauri-apps/…'`）
    //    是为了绕开"插件包没装、Web 构建解析不了"，代价有三层，全是静默的：
    //    ① TS 拿不到模块类型 ⇒ 只能 `(dialog as any)`，插件改签名也不会报；
    //    ② Vite 不静态分析 ⇒ 产物里留下运行时裸 import("@tauri-apps/plugin-dialog")，
    //       桌面壳里按 origin 解析 ⇒ 导出/导入两条功能**发货即坏**（2026-10-09 实测取证）；
    //    ③ 依赖表里没有这两个包，任何人装依赖都不会把它们带进来。
    //    现在包已入 dependencies ⇒ 用字面量导入，类型与打包都恢复正常；
    //    Web 侧靠上面的 `if (!tauriAvailable)` 提前 return，这个 chunk 永不被加载。
    const dialog = await import('@tauri-apps/plugin-dialog');
    const path = await dialog.save({ defaultPath: name });
    if (path) {
      const fs = await import('@tauri-apps/plugin-fs');
      await fs.writeTextFile(path, content);
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
    // 桌面版：dialog 选文件 + fs 读文本（同上：字面量导入，不再用 as any 蒙住签名）
    const dialog = await import('@tauri-apps/plugin-dialog');
    const path = await dialog.open({
      multiple: false,
      filters: [{ name: 'HTTP Request', extensions: ['txt', 'req', 'http'] }],
    });
    if (typeof path !== 'string') return null;
    const fs = await import('@tauri-apps/plugin-fs');
    return await fs.readTextFile(path);
  },
};

export default tauriBridge;
