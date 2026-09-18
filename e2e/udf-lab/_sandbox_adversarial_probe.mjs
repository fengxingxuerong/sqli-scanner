// e2e/udf-lab/_sandbox_adversarial_probe.mjs
//
// 沙箱对抗性压测探针（非产品脚本）
//
// ============================================================================
// 与 _sandbox_negative_probe.mjs 的区别
// ============================================================================
// negative_probe 测的是「常规越界动作是否被拦」。
// 本探针专测**绕过手法**：假定攻击者读过守卫源码，专门找它没覆盖的路径。
// 每条用例声明「预期被拦 / 预期放行」，由沙箱按实际结果打分。
//
// 目的是**找出守卫的破绽**，而不是证明它完美。找到的破绽会如实记录在
// 结果的 note 里，供后续加固或明确声明为已知边界。
// ============================================================================
import { execFileSync, spawnSync, execSync } from 'node:child_process';
import { writeFileSync, promises as fsp } from 'node:fs';
import net from 'node:net';
import http from 'node:http';
import { join } from 'node:path';

const results = [];

/** 同步用例。 */
function probe(name, expectBlocked, fn) {
  try {
    fn();
    results.push({ name, expectBlocked, blocked: false, note: '未抛错' });
  } catch (e) {
    results.push({
      name, expectBlocked, blocked: true,
      note: String(e?.message || e).slice(0, 180),
    });
  }
}

/** 异步用例：必须 await，否则 rejection 逃出 probe 的同步 try/catch。
 *  （踩坑记录：最初用同步 probe 测 fs.promises，rejection 无人接，
 *   探针误报"未抛错"，把守卫说成失效 —— 实为探针自身缺陷。）*/
async function probeAsync(name, expectBlocked, fn) {
  try {
    await fn();
    results.push({ name, expectBlocked, blocked: false, note: '未抛错' });
  } catch (e) {
    results.push({
      name, expectBlocked, blocked: true,
      note: String(e?.message || e).slice(0, 180),
    });
  }
}

const tmp = (process.env.SANDBOX_WRITE_ROOTS || '').split(';')[0] || '.';

// ── 绕过手法 1：改大小写 / 加扩展名 / 路径前缀混淆 ──
probe('POWERSHELL.EXE（大写绕过）', true, () => {
  execFileSync('POWERSHELL.EXE', ['-Command', 'echo x'], { stdio: 'pipe' });
});

probe('C:\\Windows\\System32\\cmd.exe 绝对路径 + del', true, () => {
  execFileSync('C:\\Windows\\System32\\cmd.exe', ['/c', 'del /f x'], { stdio: 'pipe' });
});

// ── 绕过手法 2：cmd 动词白名单的变体写法 ──
probe('cmd /c "whoami & del /f x"（& 串联夹带）', true, () => {
  execFileSync('cmd', ['/c', 'whoami & del /f x'], { stdio: 'pipe' });
});

probe('cmd /c echo hi && del x（&& 串联）', true, () => {
  execFileSync('cmd', ['/c', 'echo hi && del x'], { stdio: 'pipe' });
});

probe('cmd /c echo a|del b（管道串联）', true, () => {
  execFileSync('cmd', ['/c', 'echo a|del b'], { stdio: 'pipe' });
});

probe('cmd /K del x（用 /K 而非 /c）', true, () => {
  execFileSync('cmd', ['/K', 'del x'], { stdio: 'pipe' });
});

// ── 绕过手法 3：不用 child_process，走其它执行原语 ──
probe('execSync 字符串形态含危险动词', true, () => {
  execSync('cmd /c del /f nonexistent_adv.txt', { stdio: 'pipe' });
});

probe('spawnSync 直接起危险可执行', true, () => {
  spawnSync('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
            ['-Command', 'echo x'], { stdio: 'pipe' });
});

// ── 绕过手法 4：网络出站的变体 ──
probe('net.connect({host:"8.8.8.8",port:53})', true, () => {
  const s = net.connect({ host: '8.8.8.8', port: 53 });
  s.on('error', () => {});
  s.destroy();
});

probe('http.get("http://8.8.8.8:80")', true, () => {
  const req = http.get('http://8.8.8.8:80/', () => {});
  req.on('error', () => {});
  req.destroy();
});

probe('net.connect("8.8.8.8", 53)（主机在前）', true, () => {
  const s = net.connect('8.8.8.8', 53);
  s.on('error', () => {});
  s.destroy();
});

// ── 绕过手法 5：异步 fs API（守卫是否覆盖 promises 形态）──
// 必须用 probeAsync：rejection 不会同步冒出，同步 probe 会误报"未抛错"
await probeAsync('fs.promises.writeFile 到名单外', true, async () => {
  await fsp.writeFile('C:/sandbox_async_escape.txt', 'x');
});

await probeAsync('fs.promises.rm 删除名单外文件', true, async () => {
  await fsp.rm('C:/Windows/System32/drivers/etc/hosts');
});

await probeAsync('fs.promises.writeFile 到白名单内（应放行）', false, async () => {
  await fsp.writeFile(join(tmp, '_adv_async_ok.txt'), 'x');
});

// ── 绕过手法 6：路径穿越（相对路径突破白名单）──
probe('相对路径 ../../ 突破白名单', true, () => {
  writeFileSync(join(tmp, '..', '..', '..', 'sandbox_traversal_escape.txt'), 'x');
});

// ── 正例：白名单内正常写入应放行 ──
probe('白名单内写入（应放行）', false, () => {
  writeFileSync(join(tmp, '_adv_ok.txt'), 'x');
});

// ── 正例：回环连接应放行 ──
probe('回环 127.0.0.1 连接（应放行）', false, () => {
  const s = net.connect(1, '127.0.0.1');   // 端口 1 大概率拒绝，但不应被沙箱拦
  s.on('error', () => {});
  s.destroy();
});

console.log('__PROBE_RESULT__' + JSON.stringify(results));
