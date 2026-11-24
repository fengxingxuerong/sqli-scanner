// ============================================================================
// scripts/lib/buildRetry.mjs —— [D322] Maven 冷构建的有限重试判据
//
// 真因（CI #497 实证）：mvn -Pdeploy 在解析 maven-buildtime-extension:3.0.5 时
// 偶发 `Failed to read artifact descriptor`，artifact 本身在 central 返回 200，
// 上一轮 #496 同 pin 同脚本 success ⇒ 网络/仓库解析抖动，不是本仓代码缺陷。
// 只重试这类可恢复错误；编译错误等确定性失败首次即抛，不许被重试洗绿。
// ============================================================================

const TRANSIENT = [
  /failed to read artifact descriptor/i,
  /could not (?:resolve|transfer|find) artifact/i,
  /connection (?:reset|refused|timed out)/i,
  /read timed out/i,
  /download(?:ing)? from/i,
];
const DETERMINISTIC = /\bCOMPILATION ERROR\b|syntax error|parse error|non-resolvable parent/i;

/** 错误文本是否属于可重试的依赖解析 / 网络抖动。 */
export function isTransientBuildError(text) {
  const s = String(text || '');
  if (DETERMINISTIC.test(s)) return false;
  return TRANSIENT.some((re) => re.test(s));
}

/** 归一化可注入选项，把默认值分支收敛在一处（复杂度守卫：withBuildRetry 须保持低分支）。 */
function normalizeOptions(opts) {
  const attempts = Number.isInteger(opts.attempts) && opts.attempts > 0 ? opts.attempts : 3;
  const sleep = typeof opts.sleep === 'function'
    ? opts.sleep : (ms) => new Promise((r) => setTimeout(r, ms));
  const onRetry = typeof opts.onRetry === 'function' ? opts.onRetry : () => {};
  const backoff = Number.isFinite(opts.backoffMs) && opts.backoffMs >= 0 ? opts.backoffMs : 2000;
  return { attempts, sleep, onRetry, backoff };
}

/**
 * 有限重试执行器。run 收到当前尝试序号（从 1 起），抛错由本函数裁决是否重试。
 * sleep / onRetry 可注入，便于单测不真等退避。
 */
export async function withBuildRetry(run, opts = {}) {
  const { attempts, sleep, onRetry, backoff } = normalizeOptions(opts);
  let last;
  for (let i = 1; i <= attempts; i++) {
    try {
      return await run(i);
    } catch (error) {
      last = error;
      if (i === attempts || !isTransientBuildError(error?.message || error)) throw error;
      const delay = backoff * i;
      onRetry({ attempt: i, of: attempts, delay, reason: String(error?.message || error) });
      if (delay > 0) await sleep(delay);
    }
  }
  throw last; // 不可达：循环内已抛；保留以消灭「循环永不返回」的静态告警
}
