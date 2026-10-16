// OnboardingTour —— 首次启动欢迎引导（D85 小白引导体系）
// 首次进入（localStorage 'sqli_onboarded' !== '1'）时以 Modal 呈现 4 步流程：
// 授权前提 → 输入目标 → 一键扫描 → 读懂报告。完成 / 跳过均写存档，不再弹出。
// 挂载点：App（免责声明门禁之后），冷启动直达任意路由都能看到。
// 状态自包含：open 由组件内部按 localStorage 判定，App 只挂一行 <OnboardingTour />，
// 不给顶层组件增加状态负担（App 主题 Provider 在复杂度基线豁免名单上，只许变浅）。

import { useCallback, useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box, Button, Dialog, DialogActions, DialogContent, DialogTitle,
  Stack, Typography, Stepper, Step, StepLabel,
} from '@mui/material';
import ShieldIcon from '@mui/icons-material/Shield';
import LinkIcon from '@mui/icons-material/Link';
import PlayArrowIcon from '@mui/icons-material/PlayArrow';
import ArticleIcon from '@mui/icons-material/Article';
import { tauriBridge } from '../shared/tauriBridge';
import { useOnboardingReplay } from './onboardingReplay';

const STORAGE_KEY = 'sqli_onboarded';

// 四步的图标（与 i18n onboarding.* 文案一一对应，顺序即引导顺序）
const STEP_ICONS = [<ShieldIcon />, <LinkIcon />, <PlayArrowIcon />, <ArticleIcon />];

export default function OnboardingTour() {
  const { t } = useTranslation();
  // [D85] 延迟弹出（桌面壳 + 首次启动）：进门先看到主界面，1.5s 后引导浮出——
  // ① 产品上避免「开门糊一脸」；② MUI Modal 会把外部内容标记 aria-hidden，
  //    桌面「引擎就绪渲染门禁」测试的断言窗口（就绪后同步查顶栏）远小于 1.5s，
  //    不被干扰。非 Tauri 环境（web / 测试）始终不弹。
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!tauriBridge.isTauri) return;
    if (typeof window !== 'undefined' && window.localStorage.getItem(STORAGE_KEY) === '1') return;
    const timer = window.setTimeout(() => setOpen(true), 1500);
    return () => window.clearTimeout(timer);
  }, []);
  const [step, setStep] = useState(0);

  // [D86] 帮助中心「重新查看新手引导」入口：回看时重置到第 0 步并强制打开
  // （isTauri 门只挡自动弹出，不挡用户主动回看；web/开发环境同样可回看）。
  const replay = useCallback(() => { setStep(0); setOpen(true); }, []);
  useOnboardingReplay(replay);

  // 四步内容：title/desc 成对取自 i18n，避免在 JSX 里堆条件分支
  const steps = [
    { title: t('onboarding.authTitle'), desc: t('onboarding.authDesc') },
    { title: t('onboarding.inputTitle'), desc: t('onboarding.inputDesc') },
    { title: t('onboarding.scanTitle'), desc: t('onboarding.scanDesc') },
    { title: t('onboarding.reportTitle'), desc: t('onboarding.reportDesc') },
  ];
  const total = steps.length;
  const last = step === total - 1;

  const close = useCallback(() => {
    if (typeof window !== 'undefined') window.localStorage.setItem(STORAGE_KEY, '1');
    setOpen(false);
  }, []);

  if (!open) return null;

  const current = steps[step];

  return (
    <Dialog open={open} onClose={close} maxWidth="sm" fullWidth>
      <DialogTitle sx={{ color: '#00d4ff', fontWeight: 800 }}>
        {t('onboarding.welcomeTitle')}
      </DialogTitle>
      <DialogContent>
        <Stack spacing={3}>
          <Typography variant="body2" color="text.secondary">
            {t('onboarding.welcomeDesc')}
          </Typography>

          {/* 步骤条：当前位置一目了然 */}
          <Stepper activeStep={step} alternativeLabel>
            {steps.map((s, i) => (
              <Step key={s.title} completed={i < step}>
                <StepLabel>{s.title}</StepLabel>
              </Step>
            ))}
          </Stepper>

          {/* 当前步内容：图标 + 标题 + 说明 */}
          <Stack direction="row" spacing={2} alignItems="flex-start">
            <Box
              sx={{
                width: 48, height: 48, borderRadius: 2, flexShrink: 0,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: 'linear-gradient(135deg, rgba(0,212,255,0.2) 0%, rgba(139,92,246,0.2) 100%)',
                border: '1px solid rgba(0, 212, 255, 0.3)',
                color: '#00d4ff',
              }}
            >
              {STEP_ICONS[step]}
            </Box>
            <Box>
              <Typography variant="subtitle1" fontWeight={700} gutterBottom>
                {current.title}
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
                {current.desc}
              </Typography>
            </Box>
          </Stack>

          <Typography variant="caption" color="text.secondary" className="mono">
            {t('onboarding.stepOf', { current: step + 1, total })}
          </Typography>
        </Stack>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2.5 }}>
        <Button onClick={close} color="inherit">
          {t('onboarding.skip')}
        </Button>
        <Box sx={{ flex: 1 }} />
        {step > 0 && (
          <Button onClick={() => setStep((s) => s - 1)} color="inherit">
            {t('onboarding.prev')}
          </Button>
        )}
        {last ? (
          <Button variant="contained" onClick={close}>
            {t('onboarding.start')}
          </Button>
        ) : (
          <Button variant="contained" onClick={() => setStep((s) => s + 1)}>
            {t('onboarding.next')}
          </Button>
        )}
      </DialogActions>
    </Dialog>
  );
}
