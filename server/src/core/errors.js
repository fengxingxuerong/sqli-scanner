// 错误码枚举与统一错误类

export const ErrorCode = {
  OK: 0,
  INVALID_TARGET: 1001, // 无效目标
  UNSUPPORTED_METHOD: 1002, // 不支持的请求方法
  INVALID_PARAM: 1003, // 入参非法
  SCAN_NOT_FOUND: 2001, // 扫描不存在/已结束
  ENGINE_BUSY: 2002, // 引擎忙
  HTTP_TIMEOUT: 3001, // HTTP 超时
  HTTP_ERROR: 3002, // HTTP 错误
  DETECT_FAILED: 4001, // 检测失败
  EXTRACT_FAILED: 5001, // 提取失败
  UNKNOWN: 9001, // 未知错误
  // OOB 带外通道（不改动既有码值）
  OOB_RECEIVER_START_FAILED: 6001, // 接收端启动失败
  OOB_DISABLED: 6002, // OOB 未启用 / 接收端未启动
  // tamper 插件
  TAMPER_INVALID_NAME: 6003, // 插件缺唯一 name
  // 二阶注入（Second-order）：检测器被调用但 config.secondOrder.enabled 未开（防御性，不改动既有码值）
  SECOND_ORDER_DISABLED: 6004,
  // 利用操作（sql-shell/file-read/file-write/os-shell）未显式声明已授权
  EXPLOIT_UNAUTHORIZED: 6005,
};

// 统一错误：携带 code 便于路由层映射响应
export class AppError extends Error {
  /**
   * @param {number} code 错误码
   * @param {string} message 中文错误信息
   */
  constructor(code = ErrorCode.UNKNOWN, message = '未知错误') {
    super(message);
    this.name = 'AppError';
    this.code = code;
  }
}

export default { ErrorCode, AppError };
