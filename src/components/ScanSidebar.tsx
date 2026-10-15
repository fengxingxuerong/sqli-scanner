// ScanSidebar —— 扫描页右侧信息栏（授权边界 + CI 门禁退出码）
// [D79 2026-10-14] 从 ScanPage 拆出：原页面组件体已超复杂度基线（227 > 187 行），
// 且这块信息栏是自成一体的「静态提示面板」——只读 i18n 文案、无状态、无副作用，
// 拆开后 ScanPage 回到基线内，侧栏本身也可独立测试/复用。
import { Box, Paper, Stack, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';

export default function ScanSidebar() {
  const { t } = useTranslation();

  return (
    <Stack spacing={2}>
      <Paper variant="outlined" sx={{ p: 2.5, borderRadius: 3 }}>
        <Typography variant="subtitle2" fontWeight={700} gutterBottom>
          {t('scan.sidebar.scopeTitle')}
        </Typography>
        <Stack spacing={1.25}>
          {[t('scan.sidebar.scopeSameOrigin'), t('scan.sidebar.scopeRedirect'), t('scan.sidebar.scopeSsrf')].map((line) => (
            <Stack key={line} direction="row" spacing={1.25} alignItems="flex-start">
              <Box sx={{ width: 6, height: 6, borderRadius: '50%', bgcolor: 'primary.main', mt: 0.9, flexShrink: 0 }} />
              <Typography variant="body2" color="text.secondary">{line}</Typography>
            </Stack>
          ))}
        </Stack>
      </Paper>

      <Paper variant="outlined" sx={{ p: 2.5, borderRadius: 3 }}>
        <Typography variant="subtitle2" fontWeight={700} gutterBottom>
          {t('scan.sidebar.exitTitle')}
        </Typography>
        <Stack spacing={0.75}>
          <Typography variant="body2" color="success.main" fontWeight={600}>{t('scan.sidebar.exit0')}</Typography>
          <Typography variant="body2" color="error.main" fontWeight={600}>{t('scan.sidebar.exit2')}</Typography>
          <Typography variant="body2" color="text.secondary" fontWeight={600}>{t('scan.sidebar.exit1')}</Typography>
        </Stack>
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1.25 }}>
          {t('scan.sidebar.exitDiff')}
        </Typography>
      </Paper>
    </Stack>
  );
}
