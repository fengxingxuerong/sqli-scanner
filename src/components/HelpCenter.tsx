// HelpCenter —— 帮助中心抽屉（D85 小白引导体系）
// TopBar「帮助」入口打开；三个 Tab：
//  · 快速上手：四步流程 + 授权法律前提
//  · 术语表：报告 / 配置里的专业词一句话解释（带实时过滤）
//  · 结果判读：退出码 / verdict / 风险等级三张判读表 + 「未检出≠没洞」告警
// 文案单一来源：i18n help.*（中英同步，parity 测试守齐）。

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  Box, Drawer, IconButton, Tab, Tabs, Typography, Stack, Alert, TextField,
  InputAdornment, Paper,
} from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import SearchIcon from '@mui/icons-material/Search';
import ShieldIcon from '@mui/icons-material/Shield';

interface HelpCenterProps {
  open: boolean;
  onClose: () => void;
}

// i18n returnObjects 取数组的统一断言（JSON 数组在 parity 测试中视为叶子，结构由测试守齐）
function useObjArray<T>(key: string): T[] {
  const { t } = useTranslation();
  return t(key, { returnObjects: true }) as unknown as T[];
}

function GuideTab() {
  const { t } = useTranslation();
  const steps = useObjArray<{ title: string; desc: string }>('help.guideSteps');
  return (
    <Stack spacing={2.5}>
      <Typography variant="body2" color="text.secondary">
        {t('help.guideIntro')}
      </Typography>
      <Alert severity="warning" icon={<ShieldIcon fontSize="small" />} variant="outlined">
        {t('help.guideAuth')}
      </Alert>
      {steps.map((s) => (
        <Paper key={s.title} variant="outlined" sx={{ p: 2, borderRadius: 2 }}>
          <Typography variant="subtitle2" fontWeight={700} sx={{ color: '#00d4ff' }} gutterBottom>
            {s.title}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
            {s.desc}
          </Typography>
        </Paper>
      ))}
    </Stack>
  );
}

function GlossaryTab() {
  const { t } = useTranslation();
  const terms = useObjArray<{ term: string; def: string }>('help.glossary');
  const [q, setQ] = useState('');
  const query = q.trim().toLowerCase();
  const shown = query
    ? terms.filter((g) => (g.term + g.def).toLowerCase().includes(query))
    : terms;
  return (
    <Stack spacing={2}>
      <Typography variant="body2" color="text.secondary">{t('help.glossaryIntro')}</Typography>
      <TextField
        size="small"
        fullWidth
        placeholder={t('help.tabGlossary')}
        value={q}
        onChange={(e) => setQ(e.target.value)}
        InputProps={{
          startAdornment: (
            <InputAdornment position="start"><SearchIcon fontSize="small" /></InputAdornment>
          ),
        }}
      />
      {shown.length === 0 && (
        <Typography variant="body2" color="text.secondary">—</Typography>
      )}
      {shown.map((g) => (
        <Box key={g.term}>
          <Typography variant="subtitle2" fontWeight={700} sx={{ color: '#00d4ff' }}>
            {g.term}
          </Typography>
          <Typography variant="body2" color="text.secondary" sx={{ lineHeight: 1.7 }}>
            {g.def}
          </Typography>
        </Box>
      ))}
    </Stack>
  );
}

// 判读表：退出码 / verdict / 风险等级三组，数据驱动一行渲染
function VerdictTable({ title, rows }: { title: string; rows: Array<{ code: string; desc: string }> }) {
  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={700} gutterBottom>{title}</Typography>
      <Stack spacing={0.75}>
        {rows.map((r) => (
          <Stack key={r.code} direction="row" spacing={1.5} alignItems="baseline">
            <Typography
              variant="body2"
              fontWeight={700}
              className="mono"
              sx={{ color: '#00d4ff', minWidth: 170, flexShrink: 0 }}
            >
              {r.code}
            </Typography>
            <Typography variant="body2" color="text.secondary">{r.desc}</Typography>
          </Stack>
        ))}
      </Stack>
    </Box>
  );
}

function VerdictTab() {
  const { t } = useTranslation();
  const exitRows = useObjArray<{ code: string; desc: string }>('help.verdictExit');
  const statusRows = useObjArray<{ code: string; desc: string }>('help.verdictStatus');
  const riskRows = useObjArray<{ code: string; desc: string }>('help.verdictRisk');
  return (
    <Stack spacing={3}>
      <VerdictTable title={t('help.verdictExitTitle')} rows={exitRows} />
      <VerdictTable title={t('help.verdictStatusTitle')} rows={statusRows} />
      <VerdictTable title={t('help.verdictRiskTitle')} rows={riskRows} />
      <Alert severity="info" variant="outlined">{t('help.verdictCaveat')}</Alert>
    </Stack>
  );
}

export default function HelpCenter({ open, onClose }: HelpCenterProps) {
  const { t } = useTranslation();
  const [tab, setTab] = useState(0);

  return (
    <Drawer anchor="right" open={open} onClose={onClose}>
      <Box
        sx={{
          width: { xs: '100vw', sm: 460 },
          display: 'flex',
          flexDirection: 'column',
          height: '100%',
          bgcolor: 'background.default',
        }}
        role="dialog"
        aria-label={t('help.title')}
      >
        {/* 头部：标题 + 副标题 + 关闭 */}
        <Stack
          direction="row"
          alignItems="flex-start"
          sx={{
            px: 2.5, py: 2,
            borderBottom: '1px solid rgba(0, 212, 255, 0.15)',
            background: 'linear-gradient(90deg, #0a0e16 0%, #111827 100%)',
          }}
        >
          <Box sx={{ flex: 1 }}>
            <Typography variant="h6" fontWeight={700} sx={{ color: '#00d4ff' }}>
              {t('help.title')}
            </Typography>
            <Typography variant="caption" color="text.secondary">
              {t('help.subtitle')}
            </Typography>
          </Box>
          <IconButton onClick={onClose} aria-label={t('help.close')} size="small">
            <CloseIcon />
          </IconButton>
        </Stack>

        <Tabs value={tab} onChange={(_, v) => setTab(v)} variant="fullWidth">
          <Tab label={t('help.tabGuide')} />
          <Tab label={t('help.tabGlossary')} />
          <Tab label={t('help.tabVerdict')} />
        </Tabs>

        <Box sx={{ p: 2.5, overflowY: 'auto', flex: 1 }}>
          {tab === 0 && <GuideTab />}
          {tab === 1 && <GlossaryTab />}
          {tab === 2 && <VerdictTab />}
        </Box>
      </Box>
    </Drawer>
  );
}
