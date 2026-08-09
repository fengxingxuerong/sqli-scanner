import winston from 'winston';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

// 解析可写日志路径：优先 <cwd>/logs/，失败回退系统临时目录。
// 引擎作为 Tauri sidecar / 在受限目录运行时 CWD 可能只读，相对路径 engine.log 会写失败，故动态探测。
function resolveLogPath() {
  const candidates = [
    path.join(process.cwd(), 'logs', 'engine.log'),
    path.join(os.tmpdir(), 'sqli-scanner', 'engine.log'),
  ];
  for (const p of candidates) {
    try {
      fs.mkdirSync(path.dirname(p), { recursive: true });
      fs.accessSync(path.dirname(p), fs.constants.W_OK);
      return p;
    } catch {
      // 该候选路径不可写，尝试下一个
    }
  }
  return candidates[candidates.length - 1];
}

// 测试/受限环境可通过 SQLI_NO_FILE_LOG=1 关闭文件日志，避免写盘权限提示（向后兼容：不设则行为不变）
const NO_FILE_LOG = process.env.SQLI_NO_FILE_LOG === '1' || process.env.SQLI_NO_FILE_LOG === 'true';
const LOG_PATH = NO_FILE_LOG ? null : resolveLogPath();

// 日志器：控制台 + 文件（warn 级别以上落盘）
const transports = [new winston.transports.Console()];
if (LOG_PATH) {
  const fileTransport = new winston.transports.File({ filename: LOG_PATH, level: 'warn' });
  // 文件不可写（如沙箱/只读目录）时静默降级，绝不影响引擎主流程
  fileTransport.on('error', () => {});
  transports.push(fileTransport);
}

export const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(
      ({ timestamp, level, message }) =>
        `[${timestamp}] [${level}] ${message}`
    )
  ),
  transports,
});

export default logger;
