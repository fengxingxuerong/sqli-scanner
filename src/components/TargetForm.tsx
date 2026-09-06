import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Box, TextField, MenuItem, Typography, Collapse, IconButton, Alert, InputAdornment, Button } from '@mui/material';
import { ExpandMore, ExpandLess, Add, UploadFile } from '@mui/icons-material';
import type { MethodType, InjectionLocation } from '../shared/types';
import { parseRequestFile } from '../shared/requestParser';
import { tauriBridge } from '../shared/tauriBridge';

// 注入点标记（参数值末尾 `*`，对标 sqlmap -p / `*` 精确注入点）
export interface InjectionMark {
  location: InjectionLocation;
  param: string;
  originalValue: string;
}

// 解析 JSON 文本中的注入点标记
function parseJsonMarks(text: string, location: InjectionLocation): InjectionMark[] {
  if (!text.trim()) return [];
  let obj: unknown;
  try { obj = JSON.parse(text); } catch { return []; }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return [];
  const marks: InjectionMark[] = [];
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    if (typeof v === 'string' && v.endsWith('*')) {
      marks.push({ location, param: k, originalValue: v.slice(0, -1) });
    }
  }
  return marks;
}

// 解析 URL 中的注入点标记
function parseUrlMarks(url: string): InjectionMark[] {
  if (!url.trim()) return [];
  const marks: InjectionMark[] = [];
  try {
    const u = new URL(url);
    for (const seg of u.pathname.split('/')) {
      if (seg.includes('*')) {
        marks.push({ location: 'url', param: seg.replace(/\*+$/g, ''), originalValue: seg.replace(/\*+$/g, '') });
      }
    }
    for (const [k, v] of u.searchParams.entries()) {
      if (v.endsWith('*')) marks.push({ location: 'url', param: k, originalValue: v.slice(0, -1) });
    }
  } catch { /* ignore */ }
  return marks;
}

// 汇总注入点标记
export function parseInjectionMarks(input: { url: string; bodyText: string; cookieText: string; headerText: string }): InjectionMark[] {
  return [
    ...parseUrlMarks(input.url),
    ...parseJsonMarks(input.bodyText, 'body'),
    ...parseJsonMarks(input.cookieText, 'cookie'),
    ...parseJsonMarks(input.headerText, 'header'),
  ];
}

interface TargetFormProps {
  url: string;
  method: MethodType;
  bodyText: string;
  cookieText: string;
  headerText: string;
  onChange: (patch: { url?: string; method?: MethodType; bodyText?: string; cookieText?: string; headerText?: string }) => void;
}

export default function TargetForm({ url, method, bodyText, cookieText, headerText, onChange }: TargetFormProps) {
  const { t } = useTranslation();
  const [openAdvanced, setOpenAdvanced] = useState(false);
  const [importHint, setImportHint] = useState<{ kind: 'info' | 'error'; msg: string } | null>(null);
  const marks = parseInjectionMarks({ url, bodyText, cookieText, headerText });

  // 对标 sqlmap -r：从请求文件导入完整 HTTP 请求 → 填充 URL/method/headers/body/cookie
  const handleImportRequestFile = async () => {
    setImportHint(null);
    try {
      const content = await tauriBridge.openTextFile('.txt,.req,.http');
      if (content == null) return; // 用户取消
      const parsed = parseRequestFile(content);
      if (!parsed) {
        setImportHint({ kind: 'error', msg: t('targetForm.importFailed') });
        return;
      }
      const patch: Parameters<typeof onChange>[0] = {
        url: parsed.url,
        method: parsed.method,
        bodyText: parsed.bodyText,
        cookieText: parsed.cookieText,
        headerText: parsed.headerText,
      };
      onChange(patch);
      const paramNames = Object.keys(parsed.params);
      setImportHint({
        kind: 'info',
        msg: paramNames.length
          ? t('targetForm.importedWithParams', { method: parsed.method, count: paramNames.length })
          : t('targetForm.imported', { method: parsed.method }),
      });
      // 自动展开高级参数区，便于核对导入的 body/cookie/header
      if (parsed.bodyText || parsed.cookieText || parsed.headerText) setOpenAdvanced(true);
    } catch {
      setImportHint({ kind: 'error', msg: t('targetForm.importFailed') });
    }
  };

  return (
    <Box className="space-y-3">
      {/* 核心输入：URL + 方法 */}
      <Box className="flex gap-2 items-start">
        <TextField
          select
          size="small"
          label={t('targetForm.method')}
          value={method}
          onChange={(e) => onChange({ method: e.target.value as MethodType })}
          sx={{ minWidth: 100 }}
        >
          <MenuItem value="GET">GET</MenuItem>
          <MenuItem value="POST">POST</MenuItem>
          <MenuItem value="PUT">PUT</MenuItem>
          <MenuItem value="PATCH">PATCH</MenuItem>
          <MenuItem value="DELETE">DELETE</MenuItem>
        </TextField>
        <TextField
          fullWidth
          size="small"
          label={t('targetForm.url')}
          placeholder={t('scan.urlPlaceholder')}
          value={url}
          onChange={(e) => onChange({ url: e.target.value })}
          helperText={t('targetForm.urlHelper')}
          InputProps={{
            startAdornment: <InputAdornment position="start">🔗</InputAdornment>,
          }}
        />
      </Box>

      {/* 从请求文件导入（对标 sqlmap -r） */}
      <Box className="flex items-center gap-2">
        <Button
          size="small"
          variant="outlined"
          startIcon={<UploadFile />}
          onClick={handleImportRequestFile}
        >
          {t('targetForm.importRequest')}
        </Button>
        {importHint && (
          <Alert
            severity={importHint.kind === 'error' ? 'error' : 'success'}
            variant="outlined"
            className="!py-0"
            onClose={() => setImportHint(null)}
          >
            {importHint.msg}
          </Alert>
        )}
      </Box>

      {/* 展开/收起高级参数 */}
      <Box
        className="flex items-center gap-1 cursor-pointer select-none"
        onClick={() => setOpenAdvanced(!openAdvanced)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            setOpenAdvanced(!openAdvanced);
          }
        }}
      >
        <Add fontSize="small" color="action" />
        <Typography variant="caption" color="text.secondary" sx={{ userSelect: 'none' }}>
          {openAdvanced ? t('targetForm.collapseParams') : t('targetForm.addParams')}
        </Typography>
        <IconButton size="small" aria-label={openAdvanced ? t('common.collapse') : t('common.expand')}>
          {openAdvanced ? <ExpandLess fontSize="small" /> : <ExpandMore fontSize="small" />}
        </IconButton>
      </Box>

      <Collapse in={openAdvanced}>
        <Box className="space-y-2 pl-2 border-l-2 border-gray-200">
          <TextField
            fullWidth
            size="small"
            multiline
            minRows={2}
            label={t('targetForm.bodyLabel')}
            placeholder='{ "id": "1" }'
            value={bodyText}
            onChange={(e) => onChange({ bodyText: e.target.value })}
            helperText={t('targetForm.paramHelper')}
          />
          <TextField
            fullWidth
            size="small"
            multiline
            minRows={2}
            label={t('targetForm.cookieLabel')}
            placeholder='{ "PHPSESSID": "abc" }'
            value={cookieText}
            onChange={(e) => onChange({ cookieText: e.target.value })}
            helperText={t('targetForm.paramHelper')}
          />
          <TextField
            fullWidth
            size="small"
            multiline
            minRows={2}
            label={t('targetForm.headerLabel')}
            placeholder='{ "X-Forwarded-For": "1" }'
            value={headerText}
            onChange={(e) => onChange({ headerText: e.target.value })}
            helperText={t('targetForm.paramHelper')}
          />
        </Box>
      </Collapse>

      {marks.length > 0 ? (
        <Alert severity="info" variant="outlined" className="mt-2">
          {t('targetForm.marksLabel')}
          <b>{marks.map((m) => `${m.location}.${m.param}`).join(t('targetForm.marksJoinSep'))}</b>
        </Alert>
      ) : (
        <Typography variant="caption" color="text.secondary">
          {t('targetForm.marksHint')}
        </Typography>
      )}
    </Box>
  );
}