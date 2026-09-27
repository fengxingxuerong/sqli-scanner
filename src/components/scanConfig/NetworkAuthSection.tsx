// 网络与认证分段（proxy / basic / cookie / headers）—— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
import { useTranslation } from 'react-i18next';
import { Box, Typography, Stack } from '@mui/material';
import type { ScanConfig, AuthConfig } from '../../shared/types';
import type { ScanConfigSectionProps } from './sectionProps';

type OnPatch = (patch: Partial<ScanConfig>) => void;

/** 从 auth 里删一个子键；删空后整键发 null（「关闭态干净」口径） */
function authWithout(config: ScanConfig, onChange: OnPatch, key: 'basic' | 'cookie' | 'headers') {
  const next = { ...(config.auth ?? {}) } as Record<string, unknown>;
  delete next[key];
  onChange({ auth: Object.keys(next).length ? (next as AuthConfig) : null });
}

export default function NetworkAuthSection({ config, onChange }: ScanConfigSectionProps) {
  const { t } = useTranslation();

  return (
    <Box>
      <Typography variant="subtitle2" fontWeight={600} className="mb-3">{t('scanConfig.networkAuth')}</Typography>
      <Stack spacing={2}>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.proxyLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder={t('scanConfig.proxyPlaceholder')}
            aria-label={t('scanConfig.proxyLabel')}
            value={config.proxy ?? ''}
            onChange={(e) => onChange({ proxy: e.target.value.trim() || null })}
          />
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.basicAuthLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder={t('scanConfig.basicAuthPlaceholder')}
            aria-label={t('scanConfig.basicAuthLabel')}
            value={
              config.auth?.basic
                ? `${config.auth.basic.username}:${config.auth.basic.password ?? ''}`
                : ''
            }
            onChange={(e) => {
              const v = e.target.value;
              if (!v.trim()) {
                authWithout(config, onChange, 'basic');
                return;
              }
              const idx = v.indexOf(':');
              const username = idx >= 0 ? v.slice(0, idx) : v;
              const password = idx >= 0 ? v.slice(idx + 1) : '';
              onChange({ auth: { ...(config.auth ?? {}), basic: { username, password } } });
            }}
          />
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.cookieLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder={t('scanConfig.cookiePlaceholder')}
            aria-label={t('scanConfig.cookieLabel')}
            value={config.auth?.cookie ?? ''}
            onChange={(e) => {
              const v = e.target.value;
              if (!v.trim()) {
                authWithout(config, onChange, 'cookie');
                return;
              }
              onChange({ auth: { ...(config.auth ?? {}), cookie: v } });
            }}
          />
        </Box>
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.headersLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder={t('scanConfig.headersPlaceholder')}
            aria-label={t('scanConfig.headersLabel')}
            value={Object.entries(config.auth?.headers ?? {}).map(([k, v]) => `${k}:${v}`).join(' | ')}
            onChange={(e) => {
              const v = e.target.value;
              const headers: Record<string, string> = {};
              for (const pair of v.split('|')) {
                const idx = pair.indexOf(':');
                if (idx > 0) {
                  const k = pair.slice(0, idx).trim();
                  const hv = pair.slice(idx + 1).trim();
                  if (k) headers[k] = hv;
                }
              }
              if (!Object.keys(headers).length) {
                authWithout(config, onChange, 'headers');
                return;
              }
              onChange({ auth: { ...(config.auth ?? {}), headers } });
            }}
          />
        </Box>
      </Stack>
    </Box>
  );
}
