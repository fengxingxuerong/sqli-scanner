import { List, ListItemButton, ListItemText, Chip, Box, Typography } from '@mui/material';
import type { Vulnerability } from '../shared/types';
import { RISK_LABEL, TECHNIQUE_LABEL } from '../shared/constants';
import { Highlight } from './Highlight';

const RISK_COLOR: Record<string, 'error' | 'warning' | 'info' | 'default'> = {
  Critical: 'error',
  High: 'warning',
  Medium: 'info',
  Low: 'default',
};

// 漏洞列表（search 非空时对可见文本做命中高亮）
export default function VulnList({
  vulns,
  selectedId,
  onSelect,
  search,
}: {
  vulns: Vulnerability[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  search?: string;
}) {
  if (!vulns || vulns.length === 0) {
    return <Typography variant="body2" color="text.secondary">未发现漏洞</Typography>;
  }
  return (
    <List dense className="rounded border border-gray-200">
      {vulns.map((v) => (
        <ListItemButton
          key={v.id}
          selected={v.id === selectedId}
          onClick={() => onSelect(v.id)}
        >
          <ListItemText
            primary={
              <Box className="flex items-center gap-2">
                <Chip
                  label={<Highlight text={RISK_LABEL[v.riskLevel]} query={search} />}
                  color={RISK_COLOR[v.riskLevel]}
                  size="small"
                />
                <span className="text-sm">
                  <Highlight text={TECHNIQUE_LABEL[v.technique]} query={search} />
                </span>
              </Box>
            }
            secondary={
              <Highlight
                text={`注入点 ${v.pointId} · ${v.dbms || '未知库'}`}
                query={search}
              />
            }
          />
        </ListItemButton>
      ))}
    </List>
  );
}
