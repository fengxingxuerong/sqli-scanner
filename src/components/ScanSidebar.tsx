// ScanSidebar —— 扫描页右侧信息栏（授权边界 + CI 门禁退出码）
// [D79 2026-10-14] 从 ScanPage 拆出：原页面组件体已超复杂度基线（227 > 187 行），
// 且这块信息栏是自成一体的「静态提示面板」——只读 i18n 文案、无状态、无副作用，
// 拆开后 ScanPage 回到基线内，侧栏本身也可独立测试/复用。
import { Box, Stack, Typography } from '@mui/material';
import { useTranslation } from 'react-i18next';
import ShieldIcon from '@mui/icons-material/Shield';
import ExitToAppIcon from '@mui/icons-material/ExitToApp';
import CyberPanel from './cyber/CyberPanel';

export default function ScanSidebar() {
  const { t } = useTranslation();

  return (
    <Stack spacing={2}>
      {/* [D107] 授权边界：统一赛博面板外形，条目改「霓虹小方块 + 一句话」 */}
      <CyberPanel
        title={t('scan.sidebar.scopeTitle')}
        desc={t('scan.sidebar.scopeDesc')}
        icon={<ShieldIcon />}
        dense
      >
        <Stack spacing={1.25}>
          {[t('scan.sidebar.scopeSameOrigin'), t('scan.sidebar.scopeRedirect'), t('scan.sidebar.scopeSsrf')].map((line) => (
            <Stack key={line} direction="row" spacing={1.25} alignItems="flex-start">
              <Box
                sx={{
                  width: 6,
                  height: 6,
                  borderRadius: '1px',
                  bgcolor: 'var(--cy-cyan)',
                  mt: 0.9,
                  flexShrink: 0,
                  boxShadow: '0 0 6px rgba(0, 212, 255, 0.6)',
                }}
              />
              <Typography variant="body2" color="text.secondary">{line}</Typography>
            </Stack>
          ))}
        </Stack>
      </CyberPanel>

      <CyberPanel
        title={t('scan.sidebar.exitTitle')}
        desc={t('scan.sidebar.exitDesc')}
        icon={<ExitToAppIcon />}
        dense
      >
        <Stack spacing={0.75}>
          <Typography variant="body2" color="success.main" fontWeight={600}>{t('scan.sidebar.exit0')}</Typography>
          <Typography variant="body2" color="error.main" fontWeight={600}>{t('scan.sidebar.exit2')}</Typography>
          <Typography variant="body2" color="text.secondary" fontWeight={600}>{t('scan.sidebar.exit1')}</Typography>
        </Stack>
        <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1.25 }}>
          {t('scan.sidebar.exitDiff')}
        </Typography>
      </CyberPanel>
    </Stack>
  );
}
