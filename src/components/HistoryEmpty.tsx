// HistoryEmpty —— 扫描历史页空状态（图标 + 引导 CTA + 台账说明）
// [D79 2026-10-14] 从 HistoryPage 拆出：原页面组件体超复杂度基线（175 > 169 行）。
// 空态是自含区块；p-6 + maxWidth 640 收紧（原 p-10 全宽盒在 900px 容器下显得空荡）。
import { Box, Button, Typography } from '@mui/material';
import { useNavigate } from 'react-router-dom';
import HistoryIcon from '@mui/icons-material/History';
import { useTranslation } from 'react-i18next';

export default function HistoryEmpty() {
  const { t } = useTranslation();
  const navigate = useNavigate();

  return (
    <Box
      className="p-6 text-center"
      sx={{ border: 1, borderColor: 'divider', borderRadius: 2, maxWidth: 640, mx: 'auto' }}
    >
      <HistoryIcon sx={{ fontSize: 44, color: 'text.disabled', mb: 1.5 }} />
      <Typography color="text.secondary" gutterBottom>
        {t('history.empty')}
      </Typography>
      <Button variant="contained" onClick={() => navigate('/scan')} className="mt-1">
        {t('history.firstScan')}
      </Button>
      <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 2 }}>
        {t('history.emptyHint')}
      </Typography>
    </Box>
  );
}
