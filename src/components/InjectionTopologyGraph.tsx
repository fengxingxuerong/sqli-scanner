import { memo, useMemo, useState, useCallback, useEffect, useRef, forwardRef, useImperativeHandle, type ForwardedRef } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  Handle,
  Position,
  useNodesState,
  useEdgesState,
  type Node,
  type Edge,
  type NodeProps,
  type NodeMouseHandler,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Box, Chip, Typography, Drawer, IconButton, Button } from '@mui/material';
import CloseIcon from '@mui/icons-material/Close';
import FileDownloadIcon from '@mui/icons-material/FileDownload';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import { toPng, toSvg } from 'html-to-image';
import dagre from '@dagrejs/dagre';
import type { InjectionPoint, StorePointLite, InjectionLocation } from '../shared/types';

export type { InjectionPoint, StorePointLite };

export interface InjectionTopologyGraphProps {
  points: InjectionPoint[];
  baseUrl: string;
  secondOrder?: { confirmed: string[]; storePoints?: StorePointLite[] };
  /** 已确认漏洞的注入点 id 集合（detection_found 实时累积），命中参数节点加红框高亮 */
  highlightPointIds?: string[];
  height?: number;
}

export interface TopologyModel {
  nodes: Node[];
  edges: Edge[];
}

/** 暴露给父组件（报告页）的便捷导出入口 */
export interface GraphHandle {
  exportImage: (format: 'png' | 'svg') => Promise<void> | void;
}

const LOCATIONS: InjectionLocation[] = ['url', 'body', 'cookie', 'header'];
const LOCATION_LABEL: Record<InjectionLocation, string> = {
  url: 'URL 参数',
  body: '请求体',
  cookie: 'Cookie',
  header: '请求头',
};

const NODE_W: Record<string, number> = { target: 260, location: 180, param: 240, trigger: 320 };
const NODE_H = 80;
const EXPORT_W = 1600;

/**
 * 把报告全部注入点转换为「全局注入拓扑图」的 nodes/edges：
 * - 根节点是目标 URL，向下按注入位置（url/body/cookie/header）分四类中间节点；
 * - 每类下挂该位置的每个注入点参数（存储点绿色高亮）；
 * - 每个「已确认」二阶触发页作为最右列节点，由存储点经蓝色动画边连回（语义「存储 → 回显」）；
 * - 无二阶数据时退化为「目标 → 位置 → 参数」三层分布图，仍直观展示注入点全景。
 * 纯函数，便于单测，不依赖 React Flow 渲染环境。
 */
export function buildTopologyData(
  points: InjectionPoint[],
  baseUrl: string,
  secondOrder?: { confirmed: string[]; storePoints?: StorePointLite[] },
  highlightPointIds?: string[],
): TopologyModel {
  // 无注入点时没有拓扑可展示，直接返回空图（组件层也会据此渲染 null）
  if (points.length === 0) return { nodes: [], edges: [] };
  const nodes: Node[] = [];
  const edges: Edge[] = [];
  const confirmed = secondOrder?.confirmed || [];
  const hiSet = new Set(highlightPointIds || []);

  // 根节点：目标
  nodes.push({ id: 'target', type: 'target', position: { x: 0, y: 0 }, data: { url: baseUrl } });

  // 按 location 分组
  const byLoc: Record<string, InjectionPoint[]> = {};
  for (const loc of LOCATIONS) byLoc[loc] = [];
  for (const p of points) {
    const loc = (p.location || 'url') as InjectionLocation;
    if (!byLoc[loc]) byLoc[loc] = [];
    byLoc[loc].push(p);
  }

  // 确认触发页节点（最右列），先建避免重复
  const triggerIds: string[] = [];
  confirmed.forEach((u, i) => {
    const tid = `trig-${i}`;
    triggerIds.push(tid);
    nodes.push({ id: tid, type: 'trigger', position: { x: 0, y: 0 }, data: { url: u } });
  });

  for (const loc of LOCATIONS) {
    const ps = byLoc[loc];
    if (!ps || ps.length === 0) continue;
    const locId = `loc-${loc}`;
    nodes.push({ id: locId, type: 'location', position: { x: 0, y: 0 }, data: { loc } });
    edges.push({
      id: `e-target-${locId}`,
      source: 'target',
      target: locId,
      style: { stroke: '#9aa4b2', strokeWidth: 1.5 },
    });
    for (const p of ps) {
      const isStore = !!p.isStorePoint;
      const pid = `p-${p.id}`;
      nodes.push({
        id: pid,
        type: 'param',
        position: { x: 0, y: 0 },
        data: {
          param: p.param,
          location: loc,
          isStore,
          storeKind: p.storeKind || null,
          pointId: p.id,
          vulnerable: hiSet.has(p.id),
        },
      });
      edges.push({
        id: `e-${locId}-${pid}`,
        source: locId,
        target: pid,
        style: { stroke: isStore ? '#2e7d32' : '#3f8cff', strokeWidth: isStore ? 2 : 1.5 },
      });
      // 二阶回显边：存储点 → 每个确认触发页
      if (isStore) {
        for (const tid of triggerIds) {
          edges.push({
            id: `e-${pid}-${tid}`,
            source: pid,
            target: tid,
            animated: true,
            style: { stroke: '#3f8cff', strokeWidth: 1.5 },
          });
        }
      }
    }
  }

  return { nodes, edges };
}

/**
 * 用 dagre 对全局拓扑做有向无环图自动布局（默认从左到右分层）：
 * 目标(rank0) → 位置(rank1) → 注入点参数(rank2) → 确认触发页(rank3)。
 * 任意数量注入点/位置都能自动分层不重叠。纯函数，便于单测。
 */
export function layoutTopology(
  nodes: Node[],
  edges: Edge[],
  options: { direction?: 'LR' | 'TB'; nodesep?: number; ranksep?: number } = {},
): Node[] {
  const { direction = 'LR', nodesep = 40, ranksep = 120 } = options;
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: direction, nodesep, ranksep });

  nodes.forEach((n) => {
    const w = NODE_W[n.type ?? 'param'] ?? 240;
    g.setNode(n.id, { width: w, height: NODE_H });
  });
  edges.forEach((e) => g.setEdge(e.source, e.target));

  dagre.layout(g);

  return nodes.map((n) => {
    const { x, y } = g.node(n.id);
    const w = NODE_W[n.type ?? 'param'] ?? 240;
    // dagre 返回中心点坐标，React Flow 用左上角，故减去半宽半高
    return { ...n, position: { x: x - w / 2, y: y - NODE_H / 2 } };
  });
}

const cardSx = (color: string, bg: string) => ({
  minWidth: 150,
  maxWidth: 300,
  p: 1,
  borderRadius: 1.5,
  border: '1px solid',
  borderColor: color,
  bgcolor: bg,
  boxShadow: 1,
});

const TargetNode = memo(({ data }: NodeProps) => {
  const d = data as { url: string };
  return (
    <Box sx={cardSx('primary.main', 'primary.light')}>
      <Handle type="source" position={Position.Right} />
      <Typography variant="caption" color="primary.dark" fontWeight={700}>
        扫描目标
      </Typography>
      <Typography variant="body2" sx={{ wordBreak: 'break-all', fontWeight: 600 }}>
        {d.url}
      </Typography>
    </Box>
  );
});
TargetNode.displayName = 'TargetNode';

const LocationNode = memo(({ data }: NodeProps) => {
  const d = data as { loc: InjectionLocation };
  return (
    <Box sx={cardSx('grey.500', 'grey.100')}>
      <Handle type="target" position={Position.Left} />
      <Handle type="source" position={Position.Right} />
      <Typography variant="caption" color="text.secondary" fontWeight={700}>
        注入位置
      </Typography>
      <Typography variant="body2" sx={{ fontWeight: 600 }}>
        {LOCATION_LABEL[d.loc] || d.loc}
      </Typography>
    </Box>
  );
});
LocationNode.displayName = 'LocationNode';

const ParamNode = memo(({ data }: NodeProps) => {
  const d = data as {
    param: string;
    location: InjectionLocation;
    isStore: boolean;
    storeKind: string | null;
    vulnerable: boolean;
  };
  const sx = d.vulnerable
    ? { ...cardSx('error.main', 'error.light'), borderWidth: 2 }
    : d.isStore
      ? cardSx('success.main', 'success.light')
      : cardSx('info.main', 'info.light');
  return (
    <Box sx={sx}>
      <Handle type="target" position={Position.Left} />
      {(d.isStore || d.vulnerable) && <Handle type="source" position={Position.Right} />}
      <Typography
        variant="caption"
        color={d.vulnerable ? 'error.dark' : d.isStore ? 'success.dark' : 'info.dark'}
        fontWeight={700}
      >
        {d.vulnerable ? '注入点参数（已确认漏洞）' : d.isStore ? '存储点参数' : '注入点参数'}
      </Typography>
      <Typography variant="body2" sx={{ wordBreak: 'break-all', fontWeight: 600 }}>
        {d.param}
      </Typography>
      <Box sx={{ display: 'flex', gap: 0.5, mt: 0.5, flexWrap: 'wrap' }}>
        <Chip
          label={LOCATION_LABEL[d.location] || d.location}
          size="small"
          color={d.isStore ? 'success' : 'info'}
          variant="outlined"
        />
        {d.vulnerable && <Chip label="✓ 已确认漏洞" size="small" color="error" />}
      </Box>
    </Box>
  );
});
ParamNode.displayName = 'ParamNode';

const TriggerNode = memo(({ data }: NodeProps) => {
  const d = data as { url: string };
  return (
    <Box sx={cardSx('warning.main', 'warning.light')}>
      <Handle type="target" position={Position.Left} />
      <Typography variant="caption" color="warning.dark" fontWeight={700}>
        二阶确认触发页
      </Typography>
      <Typography variant="body2" sx={{ wordBreak: 'break-all' }}>
        {d.url}
      </Typography>
    </Box>
  );
});
TriggerNode.displayName = 'TriggerNode';

const nodeTypes = {
  target: TargetNode,
  location: LocationNode,
  param: ParamNode,
  trigger: TriggerNode,
};

const Legend = () => (
  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1, alignItems: 'center', mb: 1 }}>
    <Chip size="small" label="目标" color="primary" variant="outlined" />
    <Chip size="small" label="位置" color="default" variant="outlined" />
    <Chip size="small" label="注入点" color="info" variant="outlined" />
    <Chip size="small" label="存储点" color="success" variant="outlined" />
    <Chip size="small" label="二阶触发页" color="warning" variant="outlined" />
    <Chip size="small" label="已确认漏洞" color="error" variant="outlined" />
    <Typography variant="caption" color="text.secondary">
      蓝/绿边：位置归属 / 存储点；蓝色动画边：存储点 → 回显触发页；可拖拽节点、滚轮缩放整理布局
    </Typography>
  </Box>
);

function InjectionTopologyGraphImpl(
  { points, baseUrl, secondOrder, highlightPointIds, height = 360 }: InjectionTopologyGraphProps,
  ref: ForwardedRef<GraphHandle>,
) {
  // 数据层（注入点 / 二阶 / 高亮）→ 纯函数拓扑；高亮变化也会触发重算以刷新红框
  const built = useMemo(
    () => buildTopologyData(points, baseUrl, secondOrder, highlightPointIds),
    [points, baseUrl, secondOrder, highlightPointIds],
  );
  // 用 React Flow 受控状态管理节点/边，使节点可拖拽（位置变更经 onNodesChange 持久化）
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selected, setSelected] = useState<Node | null>(null);
  // 容器 ref：精确选取本组件内的 React Flow viewport，避免多实例时 document.querySelector 取到首个实例
  const containerRef = useRef<HTMLDivElement>(null);

  // 注入点 / 二阶 / 高亮 变化时用 dagre 重排布局；两次数据变更之间用户拖拽位置予以保留
  useEffect(() => {
    setNodes(layoutTopology(built.nodes, built.edges));
    setEdges(built.edges);
  }, [built, setNodes, setEdges]);

  const handleNodeClick: NodeMouseHandler = (_, node) => setSelected(node);

  // 把当前 React Flow 视口序列化为 PNG/SVG 的 data URL（不触发下载）。
  // 按 dagre 实际布局计算内容边界与缩放，适配任意节点数量/位置。
  const renderImage = useCallback(async (format: 'png' | 'svg'): Promise<string | null> => {
    const viewportEl = containerRef.current?.querySelector('.react-flow__viewport') as HTMLElement | null;
    if (!viewportEl || nodes.length === 0) return null;

    const bounds = nodes.reduce(
      (acc, n) => {
        const w = NODE_W[n.type ?? 'param'] ?? 240;
        const x1 = n.position.x + w;
        const y1 = n.position.y + NODE_H;
        return {
          minX: Math.min(acc.minX, n.position.x),
          minY: Math.min(acc.minY, n.position.y),
          maxX: Math.max(acc.maxX, x1),
          maxY: Math.max(acc.maxY, y1),
        };
      },
      { minX: Infinity, minY: Infinity, maxX: -Infinity, maxY: -Infinity },
    );
    const contentW = Math.max(1, bounds.maxX - bounds.minX) + 40;
    const contentH = Math.max(1, bounds.maxY - bounds.minY) + 40;
    const exportH = Math.max(360, Math.ceil(contentH));
    const scale = Math.min(EXPORT_W / contentW, exportH / contentH, 2);
    const tx = (EXPORT_W - contentW * scale) / 2 - bounds.minX * scale;
    const ty = (exportH - contentH * scale) / 2 - bounds.minY * scale;

    const opts = {
      backgroundColor: '#ffffff',
      width: EXPORT_W,
      height: exportH,
      style: {
        width: `${EXPORT_W}px`,
        height: `${exportH}px`,
        transform: `translate(${tx}px, ${ty}px) scale(${scale})`,
      },
    };
    return format === 'svg' ? await toSvg(viewportEl, opts) : await toPng(viewportEl, opts);
  }, [nodes]);

  // 导出：序列化后触发浏览器下载。
  const handleExport = useCallback(
    async (format: 'png' | 'svg') => {
      const dataUrl = await renderImage(format);
      if (!dataUrl) return;
      const a = document.createElement('a');
      a.href = dataUrl;
      a.download = format === 'svg' ? 'injection-topology.svg' : 'injection-topology.png';
      a.click();
      if (typeof URL.revokeObjectURL === 'function' && dataUrl.startsWith('blob:')) {
        URL.revokeObjectURL(dataUrl);
      }
    },
    [renderImage],
  );

  // 暴露给父组件（报告页）的便捷导出入口：直接触发 PNG/SVG 下载，等价于图内「导出 PNG/SVG」按钮
  useImperativeHandle(
    ref,
    () => ({
      exportImage: (format: 'png' | 'svg') => handleExport(format),
    }),
    [handleExport],
  );

  // 复制图片：序列化 PNG → blob → 剪贴板；剪贴板不可用（非安全上下文/无权限）时降级为下载。
  const [copied, setCopied] = useState(false);
  const copyImage = useCallback(async () => {
    const dataUrl = await renderImage('png');
    if (!dataUrl) return;
    try {
      const blob = await (await fetch(dataUrl)).blob();
      if (
        typeof navigator !== 'undefined' &&
        navigator.clipboard?.write &&
        typeof ClipboardItem !== 'undefined'
      ) {
        await navigator.clipboard.write([new ClipboardItem({ 'image/png': blob })]);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
        return;
      }
      throw new Error('clipboard.write 不可用');
    } catch {
      const a = document.createElement('a');
      a.href = dataUrl;
      a.download = 'injection-topology.png';
      a.click();
    }
  }, [renderImage]);

  if (nodes.length === 0) return null;

  return (
    <>
      <Legend />
      <Box
        ref={containerRef}
        sx={{
          position: 'relative',
          height,
          border: '1px solid',
          borderColor: 'divider',
          borderRadius: 1,
          overflow: 'hidden',
        }}
      >
        <Box className="rp-no-print" sx={{ position: 'absolute', top: 8, right: 8, zIndex: 5, display: 'flex', gap: 1 }}>
          <Button
            size="small"
            variant="contained"
            startIcon={<FileDownloadIcon />}
            onClick={() => handleExport('png')}
          >
            导出 PNG
          </Button>
          <Button
            size="small"
            variant="outlined"
            startIcon={<FileDownloadIcon />}
            onClick={() => handleExport('svg')}
          >
            导出 SVG
          </Button>
          <Button
            size="small"
            variant="text"
            startIcon={<ContentCopyIcon />}
            onClick={copyImage}
          >
            {copied ? '已复制 ✓' : '复制图片'}
          </Button>
        </Box>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          fitView
          minZoom={0.2}
          maxZoom={2}
          proOptions={{ hideAttribution: true }}
          nodesDraggable
          nodesConnectable={false}
          elementsSelectable={false}
          onNodeClick={handleNodeClick}
        >
          <Background />
          <Controls showInteractive={false} />
        </ReactFlow>
      </Box>
      <Drawer anchor="right" open={!!selected} onClose={() => setSelected(null)}>
        {selected && (
          <Box sx={{ width: 320, p: 2, maxWidth: '90vw' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
              <Typography variant="subtitle1" fontWeight={700}>
                {selected.type === 'target'
                  ? '扫描目标'
                  : selected.type === 'location'
                    ? '注入位置'
                    : selected.type === 'param'
                      ? (selected.data as { isStore: boolean }).isStore
                        ? '存储点详情'
                        : '注入点详情'
                      : '触发页详情'}
              </Typography>
              <IconButton size="small" onClick={() => setSelected(null)} aria-label="关闭">
                <CloseIcon fontSize="small" />
              </IconButton>
            </Box>
            {selected.type === 'target' && (
              <DetailRow label="目标 URL" value={String((selected.data as { url: string }).url)} />
            )}
            {selected.type === 'location' && (
              <DetailRow
                label="位置"
                value={LOCATION_LABEL[(selected.data as { loc: InjectionLocation }).loc] || (selected.data as { loc: string }).loc}
              />
            )}
            {selected.type === 'param' && (
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                <DetailRow label="参数" value={String((selected.data as { param: string }).param)} />
                <DetailRow
                  label="位置"
                  value={
                    LOCATION_LABEL[(selected.data as { location: InjectionLocation }).location] ||
                    (selected.data as { location: string }).location
                  }
                />
                <DetailRow
                  label="类型"
                  value={(selected.data as { isStore: boolean }).isStore ? '存储点（二阶存储端）' : '普通注入点'}
                />
                {(selected.data as { vulnerable: boolean }).vulnerable && (
                  <Chip
                    label="✓ 已确认漏洞"
                    size="small"
                    color="error"
                    sx={{ mt: 1, alignSelf: 'flex-start' }}
                  />
                )}
                {(selected.data as { storeKind: string | null }).storeKind && (
                  <Chip
                    label={`分类: ${(selected.data as { storeKind: string }).storeKind}`}
                    size="small"
                    color="success"
                    variant="outlined"
                    sx={{ mt: 1, alignSelf: 'flex-start' }}
                  />
                )}
              </Box>
            )}
            {selected.type === 'trigger' && (
              <DetailRow label="回显 URL" value={String((selected.data as { url: string }).url)} />
            )}
          </Box>
        )}
      </Drawer>
    </>
  );
}

const InjectionTopologyGraph = forwardRef(InjectionTopologyGraphImpl);
export default InjectionTopologyGraph;

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <Box>
      <Typography variant="caption" color="text.secondary">
        {label}
      </Typography>
      <Typography variant="body2" sx={{ wordBreak: 'break-all', fontWeight: 600 }}>
        {value}
      </Typography>
    </Box>
  );
}
