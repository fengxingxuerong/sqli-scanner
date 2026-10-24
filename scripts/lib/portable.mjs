// ============================================================================
// scripts/lib/portable.mjs —— [D143 2026-10-23] 便携包链路的共享判据
//
// 为什么抽出来：D142 的 build-portable / portable-smoke 各自写了一份「Tauri 命名约定」
// 与「命令行选项解析」。同一约定两份实现 = 本仓反复治理的形态（README 测试数、e2e 基线、
// 版本号都是同一类），而且 duplication 门禁当场就红了（3272 → 3274）。
// 抽到一处后：命名约定只有**一个**来源，两个脚本都从这里取。
// ============================================================================
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import nodeOs from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

/**
 * 目标三元组（与 Tauri externalBin 命名约定一致；与 build-sidecar 同一张表）。
 * 不导出：只有本模块的 portableLayout / buildChecks 用它；deadcode 门禁把「无人 import 的
 * 导出」算作死代码，而它确实不需要跨模块可见（口径与仓库其它门禁一致）。
 * @param {string} platform process.platform 取值
 * @param {string} arch process.arch 取值
 * @returns {string|null} 三元组；平台/架构不认识时为 null
 */
function targetTriple(platform, arch) {
  const a = { x64: 'x86_64', arm64: 'aarch64' }[arch];
  const os = { win32: 'pc-windows-msvc', darwin: 'apple-darwin', linux: 'unknown-linux-gnu' }[platform];
  return a && os ? `${a}-${os}` : null;
}

/**
 * 便携包的文件布局（纯函数，供 CI/测试断言命名约定）。
 * `sidecar` 是构建产物名（带三元组），`sidecarDst` 是**运行期必须的名字**：
 * 壳按 `shell().sidecar("sqli-engine")` 找它 —— 少这一步就起不来，是本链路存在的首要理由。
 * @param {string} platform process.platform 取值
 * @param {string} arch process.arch 取值
 * @returns {{ ok: boolean, ext: string, shell: string, sidecar: (string|null), sidecarDst: string }} 布局
 */
export function portableLayout(platform, arch) {
  const ext = platform === 'win32' ? '.exe' : '';
  const triple = targetTriple(platform, arch);
  return {
    ok: Boolean(triple),
    ext,
    shell: `sqli-scanner${ext}`,
    sidecar: triple ? `sqli-engine-${triple}${ext}` : null,
    sidecarDst: `sqli-engine${ext}`,
  };
}

/**
 * 生成 manifest（逐文件 sha256 + 体积），交付时可逐个核对。
 * @param {string} dir 待登记目录
 * @param {{ name: string, version: string, platform: string }} meta 元信息
 * @returns {{ name: string, version: string, kind: string, platform: string, builtAt: string, files: {name: string, size: number, sha256: string}[], note: string }} manifest
 */
export function buildManifest(dir, meta) {
  const files = fs
    .readdirSync(dir)
    .filter((n) => n !== 'manifest.json')
    .sort()
    .map((name) => {
      const p = path.join(dir, name);
      return { name, size: fs.statSync(p).size, sha256: createHash('sha256').update(fs.readFileSync(p)).digest('hex') };
    });
  return {
    name: meta.name,
    version: meta.version,
    kind: 'portable',
    platform: meta.platform,
    builtAt: new Date().toISOString(),
    files,
    // 交付语义写在 manifest 里，避免接收方以为这是安装包
    note: '免安装绿色包（不是官方安装包）：解压后直接运行 sqli-scanner[.exe]；sidecar 必须与它同目录且名为 sqli-engine[.exe]。',
  };
}

/**
 * 读选项值，**两种写法都认**：`--flag value` 与 `--flag=value`。
 * （D144 实测教训：只认前者时，`--require=nope` 被当成不存在的标志 ⇒ 校验被静默跳过、
 *  脚本照常 exit 0 —— 判据形同虚设。这类「传了没生效」的红线在本仓有专名。）
 * @param {string[]} argv 参数数组
 * @param {string} name 选项名（如 `--zip`）
 * @returns {string|null} 值；缺省为 null
 */
export function readOpt(argv, name) {
  const eq = argv.find((a) => a.startsWith(`${name}=`));
  if (eq) return eq.slice(name.length + 1) || null;
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : null;
}

/**
 * 选项是否出现（同样认 `--flag` 与 `--flag=value` 两种写法）。
 * @param {string[]} argv 参数数组
 * @param {string} name 选项名
 * @returns {boolean} 是否出现
 */
export function hasFlag(argv, name) {
  return argv.includes(name) || argv.some((a) => a.startsWith(`${name}=`));
}

/**
 * 失败退出（1 = 失败，与仓库其它门禁一致：失败必须非零，绝不静默降级）。
 * @param {string} tag 日志前缀（如 `[portable]`）
 * @param {string} msg 失败原因（应写明怎么补）
 * @returns {never} 永不返回
 */
export function failWith(tag, msg) {
  console.error(`${tag} ✗ ${msg}`);
  process.exit(1);
}

/**
 * 跳过（exit 0）——**仅用于环境不满足**（如非 Windows 平台跑便携包冒烟）。
 * 调用方必须把原因写成可核对的文字，便于一眼看出「没跑」而不是「跑了通过」。
 * @param {string} tag 日志前缀
 * @param {string} msg 跳过原因
 * @returns {never} 永不返回
 */
export function skipWith(tag, msg) {
  console.log(`${tag} [SKIP] ${msg}`);
  process.exit(0);
}

/**
 * 探 `/api/health` 并取出 data 字段（sidecar 冒烟与便携包冒烟共用**同一份**实现）。
 * 任何异常（连不上/超时/非 JSON）都返回 null，由调用方的判定函数报错 —— 不在这里抛。
 * @param {number} port 监听端口
 * @returns {Promise<any|null>} data 字段；取不到为 null
 */
export function fetchHealthData(port) {
  return new Promise((resolve) => {
    const q = http.get({ host: '127.0.0.1', port, path: '/api/health', timeout: 3000 }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (d) => { body += d; });
      res.on('end', () => {
        try { resolve(JSON.parse(body)?.data ?? null); } catch { resolve(null); }
      });
    });
    q.on('error', () => resolve(null));
    q.on('timeout', () => { q.destroy(); resolve(null); });
  });
}

/**
 * 是否「被当作脚本直接运行」（import 进测试时不应触发主流程）。
 * 两个 portable 脚本共用一份，避免同一段自证式守卫各写一遍。
 * @param {string} moduleUrl 调用方的 `import.meta.url`
 * @returns {boolean} true = 直接运行
 */
export function isDirectRun(moduleUrl) {
  try {
    return Boolean(process.argv[1]) && moduleUrl === pathToFileURL(process.argv[1]).href;
  } catch {
    return false;
  }
}

/**
 * 自证harness：把「判据对合成样本必须有反应」的收尾逻辑收敛到一处。
 * 两个 portable 脚本各写一遍收尾（收集 → 逐条打印 → exit 1 → 通过文案）会让
 * duplication 门禁当场点名；这里只共享**harness**，各脚本的检查项仍各写各的。
 * @param {string} tag 日志前缀（如 `[portable]`）
 * @param {[string, boolean][]} checks [检查项描述, 是否通过] 列表
 * @param {string} covered 通过时打印的覆盖说明（一句话说清这几条判据管什么）
 * @returns {void} 有失败项时 exit 1
 */
export function runSelftest(tag, checks, covered) {
  const failed = checks.filter(([, ok]) => !ok);
  if (failed.length) {
    console.error(`${tag} ✗ selftest 失败：`);
    for (const [label] of failed) console.error(`    · ${label}`);
    process.exit(1);
  }
  console.log(`${tag} ✓ selftest 通过（${covered}；共 ${checks.length} 条判据有反应）`);
}

/**
 * 判定健康端点自报是否可信（纯函数；便携包冒烟用它，selftest 覆盖每条失败路径）。
 * @param {any} health `/api/health` 的 data 字段（取不到时为 null）
 * @param {string} expectedVersion package.json 的版本
 * @returns {string[]} 问题列表（空数组 = 通过）
 */
export function judgeHealth(health, expectedVersion) {
  if (!health) return ['/api/health 取不到响应（引擎启动失败或端口没起来）'];
  const problems = [];
  if (health.status !== 'up') problems.push(`status=${health.status}，期望 up`);
  if (health.version !== expectedVersion) {
    problems.push(
      `版本自报不符：health.version=${health.version}，package.json=${expectedVersion}` +
        '（便携包最怕这个：装到别的机器上报错版本，D128 实测过 0.0.0+unknown）'
    );
  }
  if (health.authEnabled !== true) {
    problems.push(`authEnabled=${health.authEnabled}，期望 true —— 壳注入一次性 token 的链路没生效`);
  }
  return problems;
}

/**
 * 组装脚本的自证用例：命名约定 / 三元组 / manifest（含用已知内容核对 sha256）。
 * @returns {[string, boolean][]} [检查项, 是否通过] 列表
 */
export function buildChecks() {
  const win = portableLayout('win32', 'x64');
  const linux = portableLayout('linux', 'x64');
  const tmp = fs.mkdtempSync(path.join(nodeOs.tmpdir(), 'portable-selftest-'));
  fs.writeFileSync(path.join(tmp, 'a.txt'), 'abc', 'utf8');
  const m = buildManifest(tmp, { name: 'x', version: '1.2.3', platform: 'test' });
  fs.rmSync(tmp, { recursive: true, force: true });
  const expect = createHash('sha256').update('abc').digest('hex');
  return [
    ['Windows 壳名应为 sqli-scanner.exe', win.shell === 'sqli-scanner.exe'],
    ['Windows sidecar 产物名带三元组', win.sidecar === 'sqli-engine-x86_64-pc-windows-msvc.exe'],
    ['Windows sidecar 交付名必须是 sqli-engine.exe（Tauri 命名约定）', win.sidecarDst === 'sqli-engine.exe'],
    ['Linux sidecar 交付名必须是 sqli-engine', linux.sidecarDst === 'sqli-engine'],
    ['不支持的平台必须报 ok=false（不能编三元组）', portableLayout('sunos', 'x64').ok === false],
    ['darwin/arm64 三元组正确', targetTriple('darwin', 'arm64') === 'aarch64-apple-darwin'],
    ['readOpt 能取值', readOpt(['--zip', 'x.zip'], '--zip') === 'x.zip'],
    ['readOpt 认 --flag=value 写法（D144 教训：只认空格写法会静默跳过校验）', readOpt(['--zip=y.zip'], '--zip') === 'y.zip'],
    ['readOpt 缺值返回 null', readOpt(['--zip'], '--zip') === null],
    ['hasFlag 认两种写法', hasFlag(['--up=dvwa'], '--up') === true && hasFlag(['--up', 'dvwa'], '--up') === true],
    ['hasFlag 不误判前缀（--u 不等于 --up）', hasFlag(['--u'], '--up') === false],
    ['manifest 只登记一个文件', m.files.length === 1],
    ['manifest 的 sha256 与内容一致（判据有牙）', m.files[0]?.sha256 === expect],
    ['manifest 元信息字段正确', m.version === '1.2.3' && m.kind === 'portable'],
  ];
}

/**
 * 便携包冒烟的自证用例：版本 / 鉴权 / 状态 / 缺失响应，外加命名约定。
 * @returns {[string, boolean][]} [检查项, 是否通过] 列表
 */
export function smokeChecks() {
  const ok = { status: 'up', version: '1.2.0', authEnabled: true, versionSource: 'env:ENGINE_VERSION' };
  return [
    ['正常 payload 不报问题', judgeHealth(ok, '1.2.0').length === 0],
    ['版本不符必须报出', judgeHealth(ok, '1.2.1').some((p) => p.includes('版本自报不符'))],
    ['authEnabled=false 必须报出', judgeHealth({ ...ok, authEnabled: false }, '1.2.0').some((p) => p.includes('authEnabled'))],
    ["authEnabled='true'（字符串）不得算通过（判据要认布尔）", judgeHealth({ ...ok, authEnabled: 'true' }, '1.2.0').length > 0],
    ['status 非 up 必须报出', judgeHealth({ ...ok, status: 'starting' }, '1.2.0').some((p) => p.includes('status='))],
    ['取不到响应必须报出', judgeHealth(null, '1.2.0').some((p) => p.includes('取不到响应'))],
    ['便携包按 sqli-engine.exe 找 sidecar（Tauri 命名约定）', portableLayout('win32', 'x64').sidecarDst === 'sqli-engine.exe'],
  ];
}