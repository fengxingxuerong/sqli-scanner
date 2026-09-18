// e2e/udf-lab/_sandbox_negative_probe.mjs —— 沙箱负向验证探针（非产品脚本）
//
// 目的：量出沙箱「实际能拦住什么」，而不是声称「什么都拦得住」。
// 每个用例故意违规，脚本自己记录「是否被拦」并原样输出，
// 由上层（sandbox.py 的 --expect 校验）判定，避免探针自证。
//
// 重要：本文件必须用 ESM 语法（.mjs 无 require）。
import { execFileSync } from 'node:child_process';
import { writeFileSync, copyFileSync } from 'node:fs';
import { join } from 'node:path';
import net from 'node:net';

const results = [];

function probe(name, expectBlocked, fn) {
  try {
    fn();
    results.push({ name, expectBlocked, blocked: false, note: '未抛错' });
  } catch (e) {
    results.push({
      name,
      expectBlocked,
      blocked: true,
      note: String(e?.message || e).slice(0, 160),
    });
  }
}

// ① 白名单外可执行：预期拦截
probe('执行 powershell（不在白名单）', true, () => {
  execFileSync('powershell', ['-Command', 'echo hi'], { stdio: 'pipe' });
});

// ② cmd 跑危险命令：预期拦截（del 不在动词白名单）
probe('cmd /c del 危险命令', true, () => {
  execFileSync('cmd', ['/c', 'del /f /q nonexistent_zzz.txt'], { stdio: 'pipe' });
});

// ③ 白名单外文件写入：预期拦截
probe('写入 C:/ 根目录外路径', true, () => {
  writeFileSync('C:/sandbox_escape_probe.txt', 'x');
});

// ④ 非白名单网络出站：预期拦截
probe('连接 8.8.8.8:53', true, () => {
  const s = net.connect(53, '8.8.8.8');
  s.on('error', () => {});
  s.destroy();
});

// ⑤ cmd /c echo（动词白名单内）
//    预期取决于授权状态：未授权(--allow-command-exec 未给)时，任何 cmd 调用都应被拒；
//    已授权时，白名单内动词应放行。这样探针在两种模式下都是有效的判据。
const cmdAuthorized = process.env.SANDBOX_ALLOW_COMMAND_EXEC === '1';
probe(`cmd /c echo（${cmdAuthorized ? '已授权→应放行' : '未授权→应拦截'}）`,
      !cmdAuthorized, () => {
        execFileSync('cmd', ['/c', 'echo sandbox_ok'], { stdio: 'pipe' });
      });

// ⑥ copyFileSync：读源路径 → 写目标路径。目标在白名单内应放行。
//    回归钉（实测 2026-09-18 曾误查源路径导致正常复制 .dll 被拦）
probe('copyFileSync 源在外、目标在白名单内（应放行）', false, () => {
  const tmp = process.env.SANDBOX_WRITE_ROOTS.split(';')[0];
  copyFileSync(new URL(import.meta.url), join(tmp, '_copy_probe_target.mjs'));
});

// ⑦ copyFileSync：目标在名单外 → 预期拦截
probe('copyFileSync 目标在白名单外（应拦截）', true, () => {
  const tmp = process.env.SANDBOX_WRITE_ROOTS.split(';')[0];
  copyFileSync(new URL(import.meta.url), 'C:/sandbox_copy_escape.mjs');
});

console.log('__PROBE_RESULT__' + JSON.stringify(results));
