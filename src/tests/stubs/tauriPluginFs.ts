// Tauri 插件桩（fs）：见 stubs/tauriPluginDialog.ts 说明
import { vi } from 'vitest';

export const writeTextFile = vi.fn();
export const readTextFile = vi.fn();
export default { writeTextFile, readTextFile };
