// 非 SQL 注入分段（NoSQL / GraphQL / SSTI，仅内置引擎）—— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import { Box, Typography, Switch, Stack, FormControlLabel } from '@mui/material';
import { createScanConfigActions } from './scanConfigActions';
import type { ScanConfigSectionProps } from './sectionProps';

/** 非 SQL 注入的三类（与后端 ScanManager 的 kinds 白名单严格一致） */
const NO_SQL_KINDS = ['nosql', 'graphql', 'ssti'] as const;

export default function NoSqlSection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();
  const { patchNested } = createScanConfigActions(config, onChange);

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.noSqlTitle')}</Typography>
      {/* ── 非 SQL 注入（NoSQL / GraphQL / SSTI）[2026-09-23 UI-REACH] ─────────────
          这三类此前「引擎已实现（detectors/NoSqlInjectionDetector.js）、REST 白名单已收
          （scanRoutes.js:530）、类型与 SCAN_CONFIG_KEYS 都登记了」—— 唯独面板从未渲染过控件。
          而契约测试当时的判据是「键是否登记在 SCAN_CONFIG_KEYS」，于是它被判成「已有入口」、
          不在缺口清单里 → 假绿。真实后果：Web / 桌面端用户永远测不到 NoSQL 注入。 */}
      <FormControlLabel
        control={<Switch checked={config.noSql?.enabled ?? false} onChange={(e) => patchNested('noSql', 'enabled', e.target.checked)} />}
        label={t('scanConfig.noSqlEnable')}
      />
      <Typography variant="caption" color="text.disabled" className="block mt-1">
        {t('scanConfig.noSqlHint')}
      </Typography>
      {config.noSql?.enabled && (
        <Stack spacing={0.5} className="mt-2">
          {NO_SQL_KINDS.map((k) => {
            // kinds 缺省 = 三类全跑（后端 ScanManager:627 同义兜底），故此处也按全选显示
            const selected = config.noSql?.kinds ?? [...NO_SQL_KINDS];
            const checked = selected.includes(k);
            return (
              <FormControlLabel
                key={k}
                control={
                  <Switch
                    size="small"
                    checked={checked}
                    onChange={() =>
                      patchNested(
                        'noSql',
                        'kinds',
                        checked ? selected.filter((x) => x !== k) : [...selected, k]
                      )
                    }
                  />
                }
                label={t(`scanConfig.noSqlKind.${k}`)}
              />
            );
          })}
          <Typography variant="caption" color="text.disabled">
            {t('scanConfig.noSqlKindsHint')}
          </Typography>
        </Stack>
      )}
    </Box>
  );
}
