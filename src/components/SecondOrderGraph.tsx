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
import type { StorePointLite } from '../shared/types';

export type { StorePointLite };

export interface SecondOrderGraphProps {
  candidates: string[];
  confirmed: string[];
  storePoints?: StorePointLite[];
  height?: number;
}

export interface SecondOrderGraphModel {
  nodes: Node[];
  edges: Edge[];
}

/** 暴露给父组件（报告页）的便捷导出入口 */
export interface GraphHandle {
  exportImage: (format: 'png' | 'svg') => Promise<void> | void;
}

const NODE_W: Record<string, number> = { store: 230, trigger: 320 };
const NODE_H = 90;
const EXPORT_W = 1400;

/**
 * 把二阶注入链路数据转换为 React Flow 的 nodes/edges。
 * - 存储点节点在左列，触发页节点在右列；
 * - 仅「确认」触发页与每个存储点之间连边，表示「存储 → 回显」数据流；
 * - 候选但未确认的触发页只展示、不连线（虚位待确认）。
 * 纯函数，便于单测，不依赖 React Flow 渲染环境。
 */
export function buildGraphData(
  candidates: string[],
  confirmed: string[],
  storePoints: StorePointLite[] = [],
): SecondOrderGraphModel {
  const confirmedSet = new Set(confirmed);
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  storePoints.forEach((sp, i) => {
    nodes.push({
      id: `store-${i}`,
      type: 'store',
      position: { x: 0, y: 0 },
      data: { param: sp.param, kind: sp.storeKind || 'unknown' },
    });
  });

  candidates.forEach((url, i) => {
    const isConfirmed = confirmedSet.has(url);
    nodes.push({
      id: `trig-${i}`,
      type: 'trigger',
      position: { x: 0, y: 0 },
      data: { url, confirmed: isConfirmed },
    });
    if (isConfirmed) {
      storePoints.forEach((_, si) => {
        edges.push({
          id: `e-store-${si}-trig-${i}`,
          source: `store-${si}`,
          target: `trig-${i}`,
          animated: true,
          style: { stroke: '#3f8cff', strokeWidth: 1.5 },
        });
      });
    }
  });

  return { nodes, edges };
}

/**
 * 用 dagre 对二阶链路做有向无环图自动布局（默认从左到右分层）。
 * - 存储点排在左列、确认触发页排在右列，节点自动错开不重叠；
 * - 候选触发页无入边也按拓扑排布；
 * - 任意节点数量都能自动分层，避免手写布局在节点多时重叠/溢出。
 * 纯函数，便于单测，不依赖 React Flow 渲染环境。
 */
export function layoutGraph(
  nodes: Node[],
  edges: Edge[],
  options: { direction?: 'LR' | 'TB'; nodesep?: number; ranksep?: number } = {},
): Node[] {
  const { direction = 'LR', nodesep = 40, ranksep = 130 } = options;
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: direction, nodesep, ranksep });

  nodes.forEach((n) => {
    const w = NODE_W[n.type ?? 'trigger'] ?? 300;
    g.setNode(n.id, { width: w, height: NODE_H });
  });
  edges.forEach((e) => g.setEdge(e.source, e.target));

  dagre.layout(g);

  return nodes.map((n) => {
    const { x, y } = g.node(n.id);
    const w = NODE_W[n.type ?? 'trigger'] ?? 300;
    // dagre 返回中心点坐标，React Flow 用左上角，故减去半宽半高
    return { ...n, position: { x: x - w / 2, y: y - NODE_H / 2 } };
  });
}

const StoreNode = memo(({ data }: NodeProps) => {
  const d = data as { param: string; kind: string };
  return (
    <Box
      sx={{
        minWidth: 170,
        maxWidth: 220,
        p: 1,
        borderRadius: 1.5,
        border: '1px solid',
        borderColor: 'success.main',
        bgcolor: 'success.light',
        boxShadow: 1,
      }}
    >
      <Handle type="source" position={Position.Right} />
      <Typography variant="caption" color="success.dark" fontWeight={700}>
        存储点
      </Typography>
      <Typography variant="body2" sx={{ wordBreak: 'break-all', fontWeight: 600 }}>
        {d.param}
      </Typography>
      <Chip
        label={d.kind}
        size="small"
        color="success"
        variant="outlined"
        sx={{ mt: 0.5 }}
      />
    </Box>
  );
});
StoreNode.displayName = 'StoreNode';

const TriggerNode = memo(({ data }: NodeProps) => {
  const d = data as { url: string; confirmed: boolean };
  return (
    <Box
      sx={{
        minWidth: 230,
        maxWidth: 300,
        p: 1,
        borderRadius: 1.5,
        border: '1px solid',
        borderColor: d.confirmed ? 'primary.main' : 'divider',
        bgcolor: d.confirmed ? 'primary.light' : 'background.paper',
        boxShadow: 1,
      }}
    >
      <Handle type="target" position={Position.Left} />
      <Typography
        variant="caption"
        color={d.confirmed ? 'primary.dark' : 'text.secondary'}
        fontWeight={700}
      >
        {d.confirmed ? '确认触发页' : '候选触发页'}
      </Typography>
      <Typography variant="body2" sx={{ wordBreak: 'break-all' }}>
        {d.url}
      </Typography>
    </Box>
  );
});
TriggerNode.displayName = 'TriggerNode';

const nodeTypes = { store: StoreNode, trigger: TriggerNode };

function SecondOrderGraphImpl(
  { candidates, confirmed, storePoints = [], height = 320 }: SecondOrderGraphProps,
  ref: ForwardedRef<GraphHandle>,
) {
  const built = useMemo(
    () => buildGraphData(candidates, confirmed, storePoints),
    [candidates, confirmed, storePoints],
  );
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selected, setSelected] = useState<Node | null>(null);
  // 容器 ref：精确选取本组件内的 React Flow viewport，避免多实例时 document.querySelector 取到首个实例
  const containerRef = useRef<HTMLDivElement>(null);

  // 数据变化时用 dagre 重排；两次变更之间用户拖拽位置保留
  useEffect(() => {
    setNodes(layoutGraph(built.nodes, built.edges));
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
        const w = NODE_W[n.type ?? 'trigger'] ?? 300;
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
      a.download = format === 'svg' ? 'second-order-graph.svg' : 'second-order-graph.png';
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
      a.download = 'second-order-graph.png';
      a.click();
    }
  }, [renderImage]);

  if (nodes.length === 0) return null;

  return (
    <>
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
                {selected.type === 'store' ? '存储点详情' : '触发页详情'}
              </Typography>
              <IconButton size="small" onClick={() => setSelected(null)} aria-label="关闭">
                <CloseIcon fontSize="small" />
              </IconButton>
            </Box>
            {selected.type === 'store' ? (
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                <Typography variant="caption" color="text.secondary">
                  参数
                </Typography>
                <Typography variant="body2" sx={{ wordBreak: 'break-all', fontWeight: 600 }}>
                  {String((selected.data as { param: string }).param)}
                </Typography>
                <Chip
                  label={`类型: ${String((selected.data as { kind: string }).kind)}`}
                  size="small"
                  color="success"
                  variant="outlined"
                  sx={{ mt: 1, alignSelf: 'flex-start' }}
                />
              </Box>
            ) : (
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
                <Typography variant="caption" color="text.secondary">
                  URL
                </Typography>
                <Typography variant="body2" sx={{ wordBreak: 'break-all' }}>
                  {String((selected.data as { url: string }).url)}
                </Typography>
                <Chip
                  label={(selected.data as { confirmed: boolean }).confirmed ? '已确认回显' : '候选未确认'}
                  size="small"
                  color={(selected.data as { confirmed: boolean }).confirmed ? 'primary' : 'default'}
                  sx={{ mt: 1, alignSelf: 'flex-start' }}
                />
              </Box>
            )}
          </Box>
        )}
      </Drawer>
    </>
  );
}

const SecondOrderGraph = forwardRef(SecondOrderGraphImpl);
export default SecondOrderGraph;
