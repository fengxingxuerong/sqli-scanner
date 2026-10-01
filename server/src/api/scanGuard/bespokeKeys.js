// =====================================================================
// bespokeKeys.js — 不能走「通用标量透传/clamp」的键，各自需要真校验：
// sessionFile（路径逃逸拒）/ sessionDefault / dbms / cookieJar / dropSetCookie /
// parseErrors / invalidValue / knownPoint / extractScope（隐含开 enableExtract）/
// unionCols / paramDel（窄字符集）/ dumpWhere（拒分号）。
// 自 scanConfigGuard.js 拆出（纯搬移）。调用顺序在 scalarsCore 之后（enableExtract 联动）。
// =====================================================================
import { ErrorCode, AppError } from '../../core/errors.js';
import { logger } from '../../core/logger.js';
import { pickBool, clampStr } from '../scanConfigUtils.js';
import { isSafeSessionPath } from '../../core/sessionStore.js';
import { sanitizeExtractScope, EXTRACT_SCOPE_MODES } from './extractScope.js';

// ── [CFG-REACH 2026-09-20] --param-del 合法字符集。该值会直接参与请求 URL 的 split/join
// （engine/injection.js:145,155），所以不能只照抄 CLI 的「截到 1 字符」：CLI 的输入是
// 操作者自己打的，REST 的输入来自网络调用方。（取窄集合的完整口径见原注释。）
const PARAM_DEL_ALLOWED = /^[;,|^~]$/;

export function guardBespokeKeys(config, cfg) {
  // sessionFile 白名单（原逻辑不变）
  if (cfg.sessionFile !== undefined && cfg.sessionFile !== null && cfg.sessionFile !== '') {
    if (!isSafeSessionPath(cfg.sessionFile)) {
      throw new AppError(
        ErrorCode.INVALID_PARAM,
        'sessionFile 非法：仅允许工作目录下的文件名或系统临时目录内路径，拒绝绝对路径/..逃逸'
      );
    }
    config.sessionFile = cfg.sessionFile;
  }
  const sessionDefault = pickBool(cfg, 'sessionDefault');
  if (sessionDefault !== undefined) config.sessionDefault = sessionDefault;
  // [对标 sqlmap --dbms] 强制指定 DBMS：白名单校验 + 透传（scanRunner 消费跳过指纹）
  if (cfg.dbms !== undefined && cfg.dbms !== null && String(cfg.dbms).trim() !== '') {
    config.dbms = clampStr(String(cfg.dbms).trim(), '', 64);
  }

  // [P1-FIX 2026-09-05] Cookie Jar 开关：cookieJar 默认开（undefined 不写入，引擎默认 true）；
  // dropSetCookie=true 对标 sqlmap --drop-set-cookie（请求不吸收服务端 Set-Cookie）
  const cookieJarFlag = pickBool(cfg, 'cookieJar');
  if (cookieJarFlag !== undefined) config.cookieJar = cookieJarFlag;
  const dropSetCookieFlag = pickBool(cfg, 'dropSetCookie');
  if (dropSetCookieFlag !== undefined) config.dropSetCookie = dropSetCookieFlag;
  // [G4 对标 sqlmap --parse-errors] 错误响应原文/上下文进证据链（opt-in，默认 false）
  const parseErrorsFlag = pickBool(cfg, 'parseErrors');
  if (parseErrorsFlag !== undefined) config.parseErrors = parseErrorsFlag;

  // [P0 2026-09-09 实战批次] 失效值替换（对标 sqlmap --invalid-*）：仅接受三种合法模式，
  // 非法值静默丢弃（引擎侧 invalidValue.js 同样对非法模式零行为变化，双保险）。
  if (cfg.invalidValue !== undefined && cfg.invalidValue !== null) {
    const m = String(cfg.invalidValue).trim().toLowerCase();
    if (['bignum', 'logical', 'string'].includes(m)) config.invalidValue = m;
  }
  // [P0 2026-09-09 实战批次] 已知注入点直通：{ param 必填, quote?, paren?, techniques? }。
  // quote/paren 为闭合形态原文（如 quote="'" paren="))"），techniques 为技术位白名单。
  if (cfg.knownPoint !== undefined && cfg.knownPoint !== null && typeof cfg.knownPoint === 'object') {
    const kp = cfg.knownPoint;
    const out = {};
    if (kp.param != null && String(kp.param).trim() !== '') out.param = String(kp.param).trim().slice(0, 256);
    if (kp.quote != null) out.quote = String(kp.quote).slice(0, 16);
    if (kp.paren != null) out.paren = String(kp.paren).slice(0, 16);
    if (Array.isArray(kp.techniques) && kp.techniques.length) {
      const TECHS_OK = ['union', 'error', 'boolean', 'time', 'stacked', 'oob', 'inline', 'second_order'];
      const techs = kp.techniques.map(String).filter((t) => TECHS_OK.includes(t));
      if (techs.length) out.techniques = [...new Set(techs)];
    }
    if (out.param) config.knownPoint = out;
  }

  // ── [2026-09-23 E2] 枚举 / 拖库动作族（对标 sqlmap --dbs/--tables/--dump-all/--users/…）──
  // 校验器见 sanitizeExtractScope（含「为何不做字符集白名单」的口径说明）。
  // 非法/形状不对时**丢弃并 warn**，而不是抛错：与其它配置键口径一致（配置片段不该让整次扫描失败），
  // 但必须喊出来——静默丢弃正是本仓库反复踩的那类假阴性。
  if ('extractScope' in cfg) {
    const scope = sanitizeExtractScope(cfg.extractScope);
    if (scope) {
      config.extractScope = scope;
      // [P0-FIX 2026-09-28 接口靶场] 显式枚举意图 ⇒ 必须真的进入提取阶段。
      //   引擎只在 config.enableExtract 为真时才跑提取（scan/extract.js:32、
      //   scan/finalize.js:45 的 report.data 同判据），而 REST 侧收了 extractScope
      //   却不会顺带打开 enableExtract ⇒ 传 {mode:'dbs'} 拿到 200 + 空 data，
      //   又一次"能力在、入口缺一半"的静默假阴性。
      //   CLI 早就是这道口径：bin/cli/config.js:129 `enableExtract: args.dump || enumActive`
      //   —— 这里与 CLI 对齐，而不是新发明一套语义。
      if (!config.enableExtract) {
        config.enableExtract = true;
        logger.info(
          `extractScope(mode=${scope.mode}) 已隐含开启 enableExtract：提取阶段将向目标发出大量读请求（受限速与 dumpMaxRows 约束）`
        );
      }
    } else {
      logger.warn(
        `extractScope 形状非法已丢弃（不会执行任何枚举/拖库）：${JSON.stringify(cfg.extractScope).slice(0, 200)}` +
        `（mode 需为 ${[...EXTRACT_SCOPE_MODES].join('|')} 之一）`
      );
    }
  }

  // ── [CFG-REACH 2026-09-20] 两个不能走「通用标量透传」的键，各自需要真校验 ──
  // unionCols：引擎按 Number() 用（UnionDetector.js:119）并当作「固定列数」直接喂进二分。
  // 通用透传会把 "abc" 原样带下去 → NaN 参与列数判定；"99999" 则会以固定列数名义
  // 构造超宽 UNION。这里收敛成 1..200 的整数，非法值丢弃并说明（不静默）。
  if ('unionCols' in cfg) {
    const n = Number(String(cfg.unionCols).trim());
    if (Number.isInteger(n) && n >= 1 && n <= 200) config.unionCols = String(n);
    else logger.warn(`unionCols ${JSON.stringify(cfg.unionCols)} 非 1..200 整数，已丢弃（保留自动列数二分）`);
  }
  // paramDel：见 PARAM_DEL_ALLOWED 注释——该值会进请求 URL，必须单字符 + 白名单。
  if ('paramDel' in cfg) {
    const d = String(cfg.paramDel ?? '');
    if (d.length === 1 && PARAM_DEL_ALLOWED.test(d)) config.paramDel = d;
    else if (d !== '') logger.warn(`paramDel ${JSON.stringify(d)} 需为 ; , | ^ ~ 中的单个字符，已丢弃`);
  }
  // dumpWhere：extractScope 把它原样拼进提取 SQL 的 WHERE 位（extractScope.js:160,219）。
  // 拒分号是因为分号是把「一个条件」变成「第二条语句」的那一步（堆叠查询）——本键只在
  // 已确认注入点之后用于收窄导出范围，没有任何合法场景需要带分号，所以这不是取舍是净收益。
  // 长度与 CLI 的 clampStr 同档（2000），空串按「不配置」处理（与其它字符串键口径一致）。
  if ('dumpWhere' in cfg) {
    const w = String(cfg.dumpWhere ?? '').trim();
    if (!w) {
      // 空 = 显式不配，与 defaults 语义一致，不告警
    } else if (w.includes(';')) {
      logger.warn('dumpWhere 含分号（堆叠查询形态），已丢弃该配置');
    } else {
      config.dumpWhere = w.slice(0, 2000);
    }
  }
}
