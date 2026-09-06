// tests/_setup.mjs — 全局测试初始化 + 清理（node:test 内置 global hooks）
// 每个测试文件退出时强制停止 OOB 接收端，防端口残留（EADDRINUSE）
// 注意：beforeExit/exit 回调不能 await，此处用同步方式清理
import { oobReceiver } from '../src/core/oobReceiver.js';

process.on('beforeExit', () => {
  // 同步清理（不等待 close 回调，但 closeAllConnections 会释放端口）
  try {
    if (oobReceiver._server) {
      if (typeof oobReceiver._server.closeAllConnections === 'function') oobReceiver._server.closeAllConnections();
      oobReceiver._server.close();
    }
    if (oobReceiver._dnsServer) {
      oobReceiver._dnsServer.close();
    }
    oobReceiver._listening = false;
    oobReceiver._port = null;
  } catch { /* ignore */ }
});