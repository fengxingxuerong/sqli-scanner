import { Box, Typography, Paper, Chip, Alert } from '@mui/material';
import type { Vulnerability } from '../shared/types';
import { RISK_LABEL, TECHNIQUE_LABEL } from '../shared/constants';
import PayloadViewer from './PayloadViewer';
import BlindTraceTimeline from './BlindTraceTimeline';

// 单漏洞详情 + Payload 展示
export default function VulnDetail({ vuln }: { vuln: Vulnerability | null }) {
  if (!vuln) {
    return (
      <Typography variant="body2" color="text.secondary">
        请选择左侧漏洞查看详情
      </Typography>
    );
  }
  return (
    <Box className="space-y-3">
      <Box className="flex items-center gap-2">
        <Chip label={RISK_LABEL[vuln.riskLevel]} color="error" size="small" />
        <Typography variant="h6">{TECHNIQUE_LABEL[vuln.technique]}</Typography>
      </Box>
      <Paper variant="outlined" className="p-3 bg-gray-50">
        <Typography variant="body2">
          <b>注入点：</b>
          {vuln.pointId}
        </Typography>
        <Typography variant="body2">
          <b>数据库：</b>
          {vuln.dbms || '未知'}
        </Typography>
        <Typography variant="body2">
          <b>说明：</b>
          {vuln.description || '-'}
        </Typography>
        {vuln.technique === 'stacked' && (
          <Alert severity="error" variant="outlined" className="mt-2">
            堆叠注入可进一步用于写文件 / 命令执行，危害极高（非本期自动利用，仅供确认）。
          </Alert>
        )}
        {vuln.oob && (
          <Alert severity="error" variant="outlined" className="mt-2">
            <Typography variant="body2" fontWeight={600} gutterBottom>
              带外回连确认（OOB）
            </Typography>
            <Typography variant="body2" sx={{ mb: 1 }}>
              目标 DBMS 已主动回连至接收端，确认无回显注入成立。仅确认、不自动拖库。
            </Typography>
            <Typography variant="caption" color="text.secondary" display="block">
              Token
            </Typography>
            <Typography
              variant="body2"
              sx={{ fontFamily: 'monospace', wordBreak: 'break-all', mb: 1 }}
            >
              {vuln.oob.token}
            </Typography>
            <Typography variant="caption" color="text.secondary" display="block">
              回连地址
            </Typography>
            <Typography
              variant="body2"
              sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
            >
              {vuln.oob.callback}
            </Typography>
          </Alert>
        )}
      </Paper>
      {vuln.trace && <BlindTraceTimeline trace={vuln.trace} />}
      <PayloadViewer payloads={vuln.payloads} />
    </Box>
  );
}
