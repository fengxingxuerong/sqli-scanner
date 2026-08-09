// tamper 桶文件：导入即注册内置插件，并导出单例 tamperRegistry。
// 任何模块 `import { obfuscateWithConfig } from '../core/tamper/applyTampers.js'`
// 都会触发内置插件注册（applyTampers.js 内部已 registerMany）。
// 本文件是"显式注册入口"，供应用启动或测试 setup 引用。
import { obfuscateWithConfig, applyTampers } from './applyTampers.js';
import { tamperRegistry } from './TamperRegistry.js';

export { tamperRegistry, obfuscateWithConfig, applyTampers };
export default tamperRegistry;
