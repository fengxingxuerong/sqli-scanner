import {
  Dialog,
  DialogTitle,
  DialogContent,
  DialogContentText,
  DialogActions,
  Button,
  Checkbox,
  FormControlLabel,
} from '@mui/material';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

// 首启一次性免责声明（对标 sqlmap / Metasploit 类安全工具的授权合规提示，S19）：
//  · 首次启动展示，勾选「已知晓」后才允许进入应用（App.tsx 负责持久化 sqli_disclaimer）
//  · Dialog 不可通过点外部 / ESC 关闭——未接受授权声明前不进入应用
//  · 确认按钮在勾选前禁用，强制用户显式知情
export default function DisclaimerDialog({
  open,
  onAccept,
}: {
  open: boolean;
  onAccept: () => void;
}) {
  const [checked, setChecked] = useState(false);
  const { t } = useTranslation();

  return (
    <Dialog open={open} disableEscapeKeyDown onClose={() => {}}>
      <DialogTitle>{t('disclaimer.title')}</DialogTitle>
      <DialogContent>
        <DialogContentText component="div">
          <p style={{ margin: '0 0 8px' }}>
            {t('disclaimer.para1')}
          </p>
          <p style={{ margin: 0 }}>
            {t('disclaimer.para2')}
          </p>
          <FormControlLabel
            sx={{ mt: 1.5 }}
            control={
              <Checkbox checked={checked} onChange={(e) => setChecked(e.target.checked)} />
            }
            label={t('disclaimer.acknowledge')}
          />
        </DialogContentText>
      </DialogContent>
      <DialogActions>
        <Button variant="contained" disabled={!checked} onClick={onAccept}>
          {t('disclaimer.enter')}
        </Button>
      </DialogActions>
    </Dialog>
  );
}
