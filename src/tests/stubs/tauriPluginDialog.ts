// Tauri 插件桩：@tauri-apps/plugin-dialog 与 @tauri-apps/plugin-fs 仅在
// Tauri 桌面构建中被动态 import（变量形式，避免 Web 构建解析），本地未安装。
// vitest.config.ts 通过 resolve.alias 将这两个说明符指到本桩，供桌面分支单测使用。
import { vi } from 'vitest';

export const save = vi.fn();
export const open = vi.fn();
export default { save, open };
