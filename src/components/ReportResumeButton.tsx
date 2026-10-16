// ReportResumeButton —— 报告页「续跑」按钮（D85 自 ReportPage 拆出）
// 自包含：内部 useScan().startScan + resumeError 状态 + 「可否续跑」判定
// （沿用 HistoryPage 口径：仅 builtin + 有会话配置时可续跑）。
// 拆移动机：ReportPage 函数体超复杂度基线（D85 加判读提示后 325 > 320 存量上限），
// 续跑块（state + async handler + JSX 约 35 行）是自成一体的交互单元；
// 拆出后 ReportPage 回到基线内，本按钮可独立测试 / 复用。

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Button, Typography } from '@mui/material';
import { PlayArrow } from '@mui/icons-material';
import { useScan } from '../hooks/useScan';
import type { ReportModel } from '../shared/types';

interface ReportResumeButtonProps {
  /** 当前报告（续跑需要 target 与会话配置） */
  report: ReportModel;
  /** 启动成功后的回调（页面自行跳转 /scan） */
  onStarted: () => void;
}

export default function ReportResumeButton({ report, onStarted }: ReportResumeButtonProps) {
  const { t } = useTranslation();
  const { startScan } = useScan();
  const [resumeError, setResumeError] = useState('');

  const resumeCfg = report.target?.config;
  const canResume =
    report.engine !== 'sqlmap' && !!resumeCfg && !!(resumeCfg.sessionFile || resumeCfg.sessionDefault);

  if (!canResume) return null;

  const handleResume = async () => {
    if (!report.target) return;
    try {
      await startScan({
        engine: 'builtin',
        url: report.target.baseUrl,
        method: report.target.method,
        bodyParams: report.target.bodyParams,
        cookieParams: report.target.cookieParams,
        headerParams: report.target.headerParams,
        config: {
          ...resumeCfg,
          sessionFile:
            resumeCfg.sessionFile || (resumeCfg.sessionDefault ? 'sqli-session-latest.json' : undefined),
          sessionDefault: resumeCfg.sessionDefault,
        },
      });
      onStarted();
    } catch (e: unknown) {
      setResumeError(e instanceof Error ? e.message : t('history.resumeFailed'));
    }
  };

  return (
    <>
      <Button
        startIcon={<PlayArrow />}
        onClick={() => void handleResume()}
        size="small"
        color="primary"
        variant="outlined"
      >
        {t('history.resume')}
      </Button>
      {resumeError && (
        <Typography variant="caption" color="error">{resumeError}</Typography>
      )}
    </>
  );
}
