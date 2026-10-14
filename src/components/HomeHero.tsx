// HomeHero —— 首页 Hero 区（赛博玻璃风）+ 主题感知取色
// [D79 2026-10-14] 从 HomePage 拆出：原首页组件体超复杂度基线（259 > 253 行、
// 圈复杂度 29 > 24）。Hero 是自成一体的展示区块（只读 theme/i18n + 一个跳转回调）。
// 取色口径：强调色原为暗底假定的硬编码（cyan #00d4ff / slate-400），默认浅色主题下
// 对比度不达 WCAG AA ⇒ 按 effectiveMode 分流：暗色保留赛博原色，浅色换同色相深变体。
import { keyframes } from '@emotion/react';
import { useNavigate } from 'react-router-dom';
import { Box, Button, Chip, Stack, Typography } from '@mui/material';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import SecurityIcon from '@mui/icons-material/Security';
import { useTranslation } from 'react-i18next';
import { useThemeMode } from '../shared/themeMode';

const fadeInUp = keyframes`
  from { opacity: 0; transform: translateY(18px); }
  to   { opacity: 1; transform: translateY(0); }
`;

export default function HomeHero() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { effectiveMode } = useThemeMode();
  const dark = effectiveMode === 'dark';
  const heroGradient = dark
    ? 'linear-gradient(135deg, #00d4ff 0%, #8b5cf6 100%)'
    : 'linear-gradient(135deg, #0284c7 0%, #6d28d9 100%)';
  const accent = dark ? '#00d4ff' : '#0369a1';

  return (
    <Box
      className="glass"
      sx={{
        borderRadius: 4,
        p: { xs: 4, md: 8 },
        position: 'relative',
        overflow: 'hidden',
        animation: `${fadeInUp} 0.55s ease-out both`,
        boxShadow: '0 0 60px rgba(0, 212, 255, 0.06)',
        '&::before': {
          content: '""', position: 'absolute', top: 0, left: 0, right: 0, height: '2px',
          background: 'linear-gradient(90deg, transparent 10%, #00d4ff 40%, #8b5cf6 60%, transparent 90%)',
          boxShadow: '0 0 8px rgba(0, 212, 255, 0.3)',
        },
      }}
    >
      <Stack spacing={1.5} alignItems="flex-start" sx={{ position: 'relative', zIndex: 1 }}>
        <Chip
          icon={<SecurityIcon />}
          label={t('app.title')}
          size="small"
          sx={{
            color: accent,
            borderColor: dark ? 'rgba(0, 212, 255, 0.3)' : 'rgba(3, 105, 161, 0.35)',
            bgcolor: dark ? 'rgba(0, 212, 255, 0.08)' : 'rgba(3, 105, 161, 0.06)',
            '& .MuiChip-icon': { color: accent },
            fontFamily: '"JetBrains Mono", monospace',
          }}
          variant="outlined"
        />
        <Typography
          component="h1"
          fontWeight={800}
          sx={{
            fontSize: { xs: 28, md: 44 },
            letterSpacing: '-0.03em',
            lineHeight: 1.1,
            background: heroGradient,
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
            backgroundClip: 'text',
          }}
        >
          {t('home.hero')}
        </Typography>
        <Typography variant="body1" sx={{ color: dark ? 'rgba(148, 163, 184, 0.9)' : 'text.secondary', maxWidth: 560 }}>
          {t('app.tagline')}
        </Typography>
        <Button
          variant="contained"
          size="large"
          endIcon={<ArrowForwardIcon />}
          onClick={() => navigate('/scan')}
          sx={{
            mt: 2,
            px: { xs: 4, md: 5 },
            py: 1.4,
            borderRadius: 2,
            fontSize: '1rem',
            fontWeight: 700,
            color: '#0a0e16',
            background: 'linear-gradient(135deg, #00d4ff 0%, #8b5cf6 100%)',
            boxShadow: '0 0 24px rgba(0, 212, 255, 0.3)',
            transition: 'transform 0.2s, box-shadow 0.2s',
            '&:hover': {
              transform: 'translateY(-2px)',
              background: 'linear-gradient(135deg, #33dfff 0%, #a78bfa 100%)',
              boxShadow: '0 0 32px rgba(0, 212, 255, 0.5)',
            },
          }}
        >
          {t('home.startScan')}
        </Button>
      </Stack>

      {/* 右下角装饰：盾牌光晕 */}
      <Box sx={{
        position: 'absolute', right: { xs: -40, md: 20 }, bottom: -20,
        opacity: 0.06, fontSize: { xs: 120, md: 200 }, pointerEvents: 'none',
      }}>
        <SecurityIcon sx={{ fontSize: 'inherit', color: '#00d4ff' }} />
      </Box>
    </Box>
  );
}
