// 网络与认证分段（proxy / basic / cookie / headers / login 编排）—— 2026-09-27 自 ScanConfigPanel 拆出，JSX 逐字迁移
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

/** [批次14 实战 P1-6] login 编排子字段更新；url/username/password 全空 = 整键删（关闭态干净） */
function setLoginField(config: ScanConfig, onChange: OnPatch, field: 'url' | 'username' | 'password', value: string) {
  const cur = { ...(config.login ?? {}) } as Record<string, unknown>;
  const trimmed = value.trim();
  if (!trimmed) delete cur[field];
  else cur[field] = trimmed;
  const hasAny = typeof cur.url === 'string' && !!cur.url;
  onChange({ login: hasAny ? (cur as NonNullable<ScanConfig['login']>) : undefined });
}

/** [D36 实战 P0-2] bearerRefresh 子字段更新；url 空 = 整键删（关闭态干净，与 setLoginField 同口径） */
function setRefreshField(
  config: ScanConfig,
  onChange: OnPatch,
  field: 'url' | 'tokenField' | 'refreshToken',
  value: string,
) {
  const cur = { ...(config.bearerRefresh ?? {}) } as Record<string, unknown>;
  const trimmed = value.trim();
  if (!trimmed) delete cur[field];
  else cur[field] = trimmed;
  const hasUrl = typeof cur.url === 'string' && !!cur.url;
  onChange({ bearerRefresh: hasUrl ? (cur as NonNullable<ScanConfig['bearerRefresh']>) : undefined });
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
        {/* [批次14 实战 P1-6] 登录编排最小版：url 有值即启用（username 建议同填，
            后端包装门按 username 存在与否判定）。字段名默认由登录页自动探测。 */}
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.loginUrlLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder={t('scanConfig.loginUrlPlaceholder')}
            aria-label={t('scanConfig.loginUrlLabel')}
            value={config.login?.url ?? ''}
            onChange={(e) => setLoginField(config, onChange, 'url', e.target.value)}
          />
          <Typography variant="caption" color="text.disabled" className="block">
            {t('scanConfig.loginUrlHint')}
          </Typography>
        </Box>
        {(config.login?.url ?? '') !== '' && (
          <Box>
            <Typography variant="caption" color="text.secondary">{t('scanConfig.loginCredLabel')}</Typography>
            <input
              className="mt-1 w-full px-3 py-2 border rounded text-sm"
              placeholder={t('scanConfig.loginCredPlaceholder')}
              aria-label={t('scanConfig.loginCredLabel')}
              value={config.login?.username ? `${config.login.username}:${config.login.password ?? ''}` : ''}
              onChange={(e) => {
                const v = e.target.value;
                const idx = v.indexOf(':');
                const user = idx >= 0 ? v.slice(0, idx) : v;
                const pass = idx >= 0 ? v.slice(idx + 1) : '';
                // 单次 patch 同时写 username/password：分两次会用同一个 stale config 互相覆盖
                const cur = { ...(config.login ?? {}) } as Record<string, unknown>;
                if (user.trim()) cur.username = user.trim();
                else delete cur.username;
                if (pass) cur.password = pass;
                else delete cur.password;
                const hasAny = typeof cur.url === 'string' && !!cur.url;
                onChange({ login: hasAny ? (cur as NonNullable<ScanConfig['login']>) : undefined });
              }}
            />
          </Box>
        )}
        {/* [D36 实战 P0-2] Bearer/Token 自动续期：与上面的表单登录是两条独立的路
            （login = 用户名密码换会话 cookie；这里 = refresh 端点换新 access token）。
            url 有值即启用；tokenField 留空则按常见字段名自动探测，探测不到时报告会写明
            「试过哪些字段 + 响应顶层有哪些键」。 */}
        <Box>
          <Typography variant="caption" color="text.secondary">{t('scanConfig.refreshUrlLabel')}</Typography>
          <input
            className="mt-1 w-full px-3 py-2 border rounded text-sm"
            placeholder={t('scanConfig.refreshUrlPlaceholder')}
            aria-label={t('scanConfig.refreshUrlLabel')}
            value={config.bearerRefresh?.url ?? ''}
            onChange={(e) => setRefreshField(config, onChange, 'url', e.target.value)}
          />
          <Typography variant="caption" color="text.disabled" className="block">
            {t('scanConfig.refreshUrlHint')}
          </Typography>
        </Box>
        {(config.bearerRefresh?.url ?? '') !== '' && (
          <Box className="grid grid-cols-2 gap-2">
            <Box>
              <Typography variant="caption" color="text.secondary">{t('scanConfig.refreshTokenFieldLabel')}</Typography>
              <input
                className="mt-1 w-full px-3 py-2 border rounded text-sm"
                placeholder="data.access_token"
                aria-label={t('scanConfig.refreshTokenFieldLabel')}
                value={config.bearerRefresh?.tokenField ?? ''}
                onChange={(e) => setRefreshField(config, onChange, 'tokenField', e.target.value)}
              />
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary">{t('scanConfig.refreshTokenLabel')}</Typography>
              <input
                className="mt-1 w-full px-3 py-2 border rounded text-sm"
                placeholder={t('scanConfig.refreshTokenPlaceholder')}
                aria-label={t('scanConfig.refreshTokenLabel')}
                value={config.bearerRefresh?.refreshToken ?? ''}
                onChange={(e) => setRefreshField(config, onChange, 'refreshToken', e.target.value)}
              />
              <Typography variant="caption" color="text.disabled" className="block">
                {t('scanConfig.refreshTokenHint')}
              </Typography>
            </Box>
          </Box>
        )}
      </Stack>
    </Box>
  );
}
