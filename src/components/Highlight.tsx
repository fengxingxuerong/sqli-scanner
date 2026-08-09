import type { ReactNode } from 'react';

// 命中高亮：将文本中匹配 query 的片段用 <mark> 包裹（忽略大小写）。
// query 为空或无匹配时原样返回，不影响默认渲染与既有测试。
export function Highlight({ text, query }: { text: string; query?: string }) {
  const q = (query || '').trim();
  if (!q) return <>{text}</>;
  const lower = text.toLowerCase();
  const ql = q.toLowerCase();
  if (!lower.includes(ql)) return <>{text}</>;

  const parts: ReactNode[] = [];
  let i = 0;
  let k = 0;
  let idx = lower.indexOf(ql, i);
  while (idx !== -1) {
    if (idx > i) parts.push(text.slice(i, idx));
    parts.push(
      <mark key={k++} style={{ backgroundColor: '#fff3a0', color: 'inherit', padding: 0 }}>
        {text.slice(idx, idx + q.length)}
      </mark>,
    );
    i = idx + q.length;
    idx = lower.indexOf(ql, i);
  }
  if (i < text.length) parts.push(text.slice(i));
  return <>{parts}</>;
}
