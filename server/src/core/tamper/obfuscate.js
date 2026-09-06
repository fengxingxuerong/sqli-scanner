// legacy 单混淆：将 AND/OR 关键词包裹内联注释，不改变语义（P1-A2：从 engine/payloads.js 下沉到 core/tamper，消除 core→engine 反向依赖）。
// 仅被 obfuscateWithConfig 的 legacy 分支消费；新体系应使用 tamper 链式插件。
export function obfuscatePayload(payload) {
  return payload
    .replace(/\s{2,}/g, ' ')
    .replace(/\bAND\b/gi, '/*!*/AND/*!*/')
    .replace(/\bOR\b/gi, '/*!*/OR/*!*/');
}

export default obfuscatePayload;
