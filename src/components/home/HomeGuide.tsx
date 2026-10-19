// ============================================================================
// HomeGuide —— 首页「三步上手」引导条（D107 桌面端 UI 全面优化）
//
// 原实现只在「历史为空」时才显示三步卡片 ⇒ 一旦有记录，新手就再也看不到用法说明。
// 现改为常驻：工具的核心用法（填 URL → 点扫描 → 看报告）任何时候都在首页可见，
// 空态只承担「还没有数据 + 去扫描」的职责。
// ============================================================================
import { useTranslation } from 'react-i18next';
import { Box, Stack, Typography } from '@mui/material';
import CyberPanel from '../cyber/CyberPanel';

export default function HomeGuide() {
  const { t } = useTranslation();
  const steps = [
    { n: '01', title: t('home.guide.step1'), desc: t('home.guide.step1Desc') },
    { n: '02', title: t('home.guide.step2'), desc: t('home.guide.step2Desc') },
    { n: '03', title: t('home.guide.step3'), desc: t('home.guide.step3Desc') },
  ];

  return (
    <CyberPanel
      title={t('home.guide.title')}
      desc={t('home.guide.desc')}
      icon={<Box className="mono" sx={{ fontSize: 16, fontWeight: 800 }}>?</Box>}
      dense
      className="mb-4"
    >
      <Stack
        direction={{ xs: 'column', md: 'row' }}
        spacing={{ xs: 1.5, md: 2 }}
        alignItems="stretch"
      >
        {steps.map((s, i) => (
          <Stack key={s.n} direction="row" spacing={1.5} alignItems="flex-start" sx={{ flex: 1, minWidth: 0 }}>
            <Box
              className="mono"
              sx={{
                width: 34,
                height: 34,
                flexShrink: 0,
                borderRadius: '50%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 800,
                fontSize: '0.78rem',
                color: 'var(--cy-bg)',
                background: 'linear-gradient(135deg, var(--cy-cyan) 0%, var(--cy-violet) 100%)',
              }}
            >
              {s.n}
            </Box>
            <Box sx={{ minWidth: 0 }}>
              <Typography variant="subtitle2" fontWeight={700}>{s.title}</Typography>
              <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 0.25, lineHeight: 1.6 }}>
                {s.desc}
              </Typography>
            </Box>
            {/* 步骤间连接线：仅宽屏横向布局下渲染，最后一步不画 */}
            {i < steps.length - 1 && (
              <Box
                aria-hidden="true"
                sx={{
                  display: { xs: 'none', md: 'block' },
                  flexShrink: 0,
                  width: 24,
                  mt: '17px',
                  borderTop: '1px dashed var(--cy-line-strong)',
                }}
              />
            )}
          </Stack>
        ))}
      </Stack>
    </CyberPanel>
  );
}
