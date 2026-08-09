import {
  Box,
  Typography,
  Grid,
  TextField,
  MenuItem,
  FormControlLabel,
  Switch,
  FormGroup,
  Checkbox,
  Divider,
  Alert,
  Slider,
  FormHelperText,
} from '@mui/material';
import type { SqlmapConfig } from '../shared/types';
import {
  SQLMAP_TECHNIQUES,
  SQLMAP_DBMS_OPTIONS,
  SQLMAP_TAMPER_PRESETS,
} from '../shared/constants';

// sqlmap 高级模式专属配置面板（映射 sqlmap CLI 常用参数）
export default function SqlmapOptions({
  config,
  onChange,
}: {
  config: SqlmapConfig;
  onChange: (patch: Partial<SqlmapConfig>) => void;
}) {
  const toggleTech = (letter: string, checked: boolean) => {
    const next = checked
      ? [...config.techniques, letter]
      : config.techniques.filter((x) => x !== letter);
    onChange({ techniques: next });
  };

  const toggleTamper = (name: string, checked: boolean) => {
    const next = checked
      ? [...config.tamper, name]
      : config.tamper.filter((x) => x !== name);
    onChange({ tamper: next });
  };

  const anyDestructive = config.dump || config.osShell || !!config.fileRead;

  return (
    <Box className="space-y-3">
      <Alert severity="info" variant="outlined">
        高级模式：后端调用 <b>sqlmap</b>。无需记忆命令行——下方选项会翻译为 sqlmap 参数。破坏性操作（拖库 / OS Shell / 读文件）需显式开启，且仅在<b>已授权目标</b>上使用。
      </Alert>

      <Grid container spacing={2}>
        <Grid item xs={6} md={3}>
          <TextField
            select
            fullWidth
            label="检测等级 level"
            value={config.level}
            onChange={(e) => onChange({ level: Number(e.target.value) })}
            helperText="1-5，越高越全越慢"
          >
            {[1, 2, 3, 4, 5].map((n) => (
              <MenuItem key={n} value={n}>{n}</MenuItem>
            ))}
          </TextField>
        </Grid>
        <Grid item xs={6} md={3}>
          <TextField
            select
            fullWidth
            label="风险等级 risk"
            value={config.risk}
            onChange={(e) => onChange({ risk: Number(e.target.value) })}
            helperText="1-3，越高越激进"
          >
            {[1, 2, 3].map((n) => (
              <MenuItem key={n} value={n}>{n}</MenuItem>
            ))}
          </TextField>
        </Grid>
        <Grid item xs={6} md={3}>
          <TextField
            select
            fullWidth
            label="后端 DBMS"
            value={config.dbms ?? ''}
            onChange={(e) => onChange({ dbms: e.target.value || null })}
            helperText="留空=自动识别"
          >
            <MenuItem value="">自动识别</MenuItem>
            {SQLMAP_DBMS_OPTIONS.map((o) => (
              <MenuItem key={o.value} value={o.value}>{o.label}</MenuItem>
            ))}
          </TextField>
        </Grid>
        <Grid item xs={12} md={3}>
          <Box>
            <Box className="flex items-center justify-between">
              <Typography variant="caption" color="text.secondary">线程数 threads</Typography>
              <Typography variant="body2" fontWeight={600}>{config.threads}</Typography>
            </Box>
            <Slider
              min={1}
              max={10}
              step={1}
              value={config.threads}
              aria-label="线程数 threads"
              onChange={(_, v) => onChange({ threads: v as number })}
              valueLabelDisplay="auto"
              marks={[
                { value: 1, label: '1' },
                { value: 10, label: '10' },
              ]}
              size="small"
            />
          </Box>
          <FormHelperText>1-10</FormHelperText>
        </Grid>
      </Grid>

      <Divider className="my-2" />
      <Typography variant="subtitle2" fontWeight={600} color="text.secondary">
        检测技术（B/E/U/S/T/Q）
      </Typography>
      <FormGroup row>
        {SQLMAP_TECHNIQUES.map((t) => (
          <FormControlLabel
            key={t.letter}
            control={
              <Checkbox
                checked={config.techniques.includes(t.letter)}
                onChange={(e) => toggleTech(t.letter, e.target.checked)}
              />
            }
            label={`${t.letter} · ${t.label}`}
          />
        ))}
      </FormGroup>

      <Divider className="my-2" />
      <Typography variant="subtitle2" fontWeight={600} color="text.secondary">
        Tamper 脚本（WAF 绕过）
      </Typography>
      <FormGroup row>
        {SQLMAP_TAMPER_PRESETS.map((name) => (
          <FormControlLabel
            key={name}
            control={
              <Checkbox
                checked={config.tamper.includes(name)}
                onChange={(e) => toggleTamper(name, e.target.checked)}
              />
            }
            label={name}
          />
        ))}
      </FormGroup>

      <Divider className="my-2" />
      <Typography variant="subtitle2" fontWeight={600} color="text.secondary">
        破坏性操作（需已授权目标）
      </Typography>
      <Grid container spacing={2}>
        <Grid item xs={12} md={4} className="flex items-center">
          <FormControlLabel
            control={
              <Switch
                checked={config.dump}
                onChange={(e) => onChange({ dump: e.target.checked })}
              />
            }
            label="拖库 --dump"
          />
        </Grid>
        <Grid item xs={12} md={4} className="flex items-center">
          <FormControlLabel
            control={
              <Switch
                checked={config.osShell}
                onChange={(e) => onChange({ osShell: e.target.checked })}
              />
            }
            label="OS Shell --os-shell"
          />
        </Grid>
        <Grid item xs={12} md={4}>
          <TextField
            fullWidth
            label="读文件 --file-read"
            placeholder="如 /etc/passwd"
            value={config.fileRead ?? ''}
            onChange={(e) => onChange({ fileRead: e.target.value.trim() || null })}
          />
        </Grid>
      </Grid>
      {anyDestructive && (
        <Alert severity="error" variant="outlined">
          已启用破坏性参数，将对目标执行写/读/命令操作，仅限授权环境！
        </Alert>
      )}
    </Box>
  );
}
