// SectionTitle —— 配置分区标题行（D85 小白引导体系）
// 每个分区标题右侧挂「?」富提示（InfoHint rich，点击展开长说明），
// 文案取自 i18n configHints.*（中英同步，parity 测试守齐）。
// 16 个分区共用本组件，避免在每个 Section 里重复写 Tooltip/Popover 结构
// （duplication-guard 对同构 JSX 重复块敏感，收敛到单一组件最稳）。

import { useTranslation } from 'react-i18next';
import { Stack, Typography } from '@mui/material';
import InfoHint from '../InfoHint';

interface SectionTitleProps {
  /** i18n configHints 下的键名（去掉 configHints. 前缀，如 detectionIntensity） */
  hintKey: string;
  /** 分区标题（已翻译文本） */
  children: string;
}

export default function SectionTitle({ hintKey, children }: SectionTitleProps) {
  const { t } = useTranslation();
  return (
    <Stack direction="row" alignItems="center" className="mb-3">
      <Typography variant="subtitle2" fontWeight={600}>{children}</Typography>
      <InfoHint rich title={children} text={t(`configHints.${hintKey}`)} />
    </Stack>
  );
}
