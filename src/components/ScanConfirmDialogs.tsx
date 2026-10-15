// ScanConfirmDialogs —— 两类破坏性操作的二次确认弹窗（拖库 / sqlmap 高危操作）
// [D79 2026-10-14] 从 ScanPage 拆出：原页面组件体超复杂度基线（202 > 187 行）。
// 两个对话框是自含的「授权确认」职责组：只消费开关与回调，不碰扫描状态。
import {
  Dialog, DialogTitle, DialogContent, DialogContentText, DialogActions, Button,
} from '@mui/material';
import { useTranslation } from 'react-i18next';

interface Props {
  extractOpen: boolean;
  sqlmapOpen: boolean;
  onCloseExtract: () => void;
  onConfirmExtract: () => void;
  onCloseSqlmap: () => void;
  onConfirmSqlmap: () => void;
}

export default function ScanConfirmDialogs({
  extractOpen, sqlmapOpen,
  onCloseExtract, onConfirmExtract,
  onCloseSqlmap, onConfirmSqlmap,
}: Props) {
  const { t } = useTranslation();

  return (
    <>
      {/* 自带引擎拖库二次确认 */}
      <Dialog open={extractOpen} onClose={onCloseExtract}>
        <DialogTitle>{t('scan.confirmExtract.title')}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t('scan.confirmExtract.body')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={onCloseExtract}>{t('scan.confirmExtract.cancel')}</Button>
          <Button variant="contained" color="warning" onClick={onConfirmExtract}>
            {t('scan.confirmExtract.confirm')}
          </Button>
        </DialogActions>
      </Dialog>

      {/* sqlmap 破坏性操作二次确认 */}
      <Dialog open={sqlmapOpen} onClose={onCloseSqlmap}>
        <DialogTitle>{t('scan.confirmSqlmap.title')}</DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t('scan.confirmSqlmap.body')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={onCloseSqlmap}>{t('scan.confirmSqlmap.cancel')}</Button>
          <Button variant="contained" color="error" onClick={onConfirmSqlmap}>
            {t('scan.confirmSqlmap.confirm')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
}
