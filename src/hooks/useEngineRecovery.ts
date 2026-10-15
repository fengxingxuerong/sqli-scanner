// useEngineRecovery —— 桌面版引擎生命周期 UI（D81 拆出）
// 原逻辑在 AppThemeProvider 内：engine-exit 监听 + 自动重连 + 手动重启 + 横幅状态。
// 拆出动因：① AppThemeProvider 体量/圈复杂度超基线；② 引擎重连是与主题无关的
// 独立职责。修的真 bug：start_engine 会 kill 旧 sidecar 再拉新的（端口/token 都变），
// 旧链路只 invoke 不重取信息 ⇒ 前端拿旧 token 打 401（病征：第一次扫描后每次开扫
// 都 Network Error）+ engine-exit 横幅永不消（横幅还是 startEngine 自己触发的）。
import { useCallback, useEffect, useState } from 'react';
import { tauriBridge } from '../shared/tauriBridge';

export interface EngineRecovery {
  /** 引擎掉线且自动重连未成功：显示求助横幅 */
  engineDown: boolean;
  /** 正在自动重连：显示进行态（info 级） */
  engineRecovering: boolean;
  restartEngine: () => void;
}

export function useEngineRecovery(): EngineRecovery {
  const [engineDown, setEngineDown] = useState(false);
  // [D81] 重连中与重连失败是两种可读状态：前者告知「app 在处理」，后者才求助用户
  const [engineRecovering, setEngineRecovering] = useState(false);

  // 重连并落地：重启 sidecar → 有界轮询等新就绪信息 → 应用到 apiClient → 清横幅
  const recover = useCallback(() => {
    setEngineDown(true);
    setEngineRecovering(true);
    void tauriBridge.restartEngineAndApply()
      .then((info) => { if (info) setEngineDown(false); })
      .finally(() => setEngineRecovering(false));
  }, []);

  useEffect(() => {
    if (!tauriBridge.isTauri) return;
    const unlisten = tauriBridge.onEngineExit(recover);
    return () => { if (unlisten) unlisten(); };
  }, [recover]);

  return { engineDown, engineRecovering, restartEngine: recover };
}

export default useEngineRecovery;
