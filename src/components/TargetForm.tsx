import {
  Box,
  TextField,
  MenuItem,
  Typography,
  Grid,
  InputAdornment,
} from '@mui/material';
import type { MethodType } from '../shared/types';

// 目标录入区：URL / 方法 / Body / Cookie / Header
export default function TargetForm({
  url,
  method,
  bodyText,
  cookieText,
  headerText,
  onChange,
}: {
  url: string;
  method: MethodType;
  bodyText: string;
  cookieText: string;
  headerText: string;
  onChange: (patch: {
    url?: string;
    method?: MethodType;
    bodyText?: string;
    cookieText?: string;
    headerText?: string;
  }) => void;
}) {
  return (
    <Box className="space-y-3">
      <Typography variant="subtitle1" fontWeight={600}>
        目标录入
      </Typography>
      <Grid container spacing={2}>
        <Grid item xs={12} md={3}>
          <TextField
            select
            fullWidth
            label="请求方法"
            value={method}
            onChange={(e) => onChange({ method: e.target.value as MethodType })}
          >
            <MenuItem value="GET">GET</MenuItem>
            <MenuItem value="POST">POST</MenuItem>
          </TextField>
        </Grid>
        <Grid item xs={12} md={9}>
          <TextField
            fullWidth
            label="目标 URL"
            placeholder="http://example.com/item.php?id=1"
            value={url}
            onChange={(e) => onChange({ url: e.target.value })}
            InputProps={{
              startAdornment: <InputAdornment position="start">🔗</InputAdornment>,
            }}
          />
        </Grid>
        <Grid item xs={12} md={4}>
          <TextField
            fullWidth
            multiline
            minRows={3}
            label="Body 参数 (JSON)"
            placeholder={'{\n  "id": "1"\n}'}
            value={bodyText}
            onChange={(e) => onChange({ bodyText: e.target.value })}
          />
        </Grid>
        <Grid item xs={12} md={4}>
          <TextField
            fullWidth
            multiline
            minRows={3}
            label="Cookie 参数 (JSON)"
            placeholder={'{\n  "PHPSESSID": "abc"\n}'}
            value={cookieText}
            onChange={(e) => onChange({ cookieText: e.target.value })}
          />
        </Grid>
        <Grid item xs={12} md={4}>
          <TextField
            fullWidth
            multiline
            minRows={3}
            label="Header 参数 (JSON，全局自定义 Header)"
            placeholder={'{\n  "X-Forwarded-For": "1"\n}'}
            value={headerText}
            onChange={(e) => onChange({ headerText: e.target.value })}
            helperText="目标级自定义 Header，将随每次请求发送，并与认证面板中的自定义头合并"
          />
        </Grid>
      </Grid>
    </Box>
  );
}
