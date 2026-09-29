// ============================================================================
// useServerHistory.ts —— 服务端扫描清单（GET /api/scans）的读取钩子
// ============================================================================
// 纪律：**失败不得让页面变空白**。服务端拿不到（未鉴权 / 引擎没起 / 网络断了）时
// 返回空 rows + error 文案，页面按 mergeHistory 退回本地历史并如实提示用户。
// 这是"服务端是事实源"与"本地是兜底"之间的边界：主链路变了，但断层时不能比原来更差。
// ============================================================================
import { useEffect, useState } from 'react';
import { apiClient, type ServerScanRow } from '../shared/apiClient';

export interface ServerHistoryState {
  rows: ServerScanRow[];
  /** 首次加载中（用于给一个 loading 态，避免闪一下"没有记录"再跳成有记录） */
  loading: boolean;
  /** 空串 = 正常拿到了清单（哪怕清单是空的） */
  error: string;
}

export function useServerHistory(limit = 50): ServerHistoryState {
  const [state, setState] = useState<ServerHistoryState>({ rows: [], loading: true, error: '' });

  useEffect(() => {
    let alive = true; // 卸载后不再 setState（React 严格模式下 effect 会跑两次）
    apiClient
      .scans(limit)
      .then((data) => {
        if (!alive) return;
        setState({ rows: data?.scans || [], loading: false, error: '' });
      })
      .catch((e: unknown) => {
        if (!alive) return;
        const msg = e instanceof Error ? e.message : String(e ?? '');
        setState({ rows: [], loading: false, error: msg || '服务端清单读取失败' });
      });
    return () => {
      alive = false;
    };
  }, [limit]);

  return state;
}
