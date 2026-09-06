import { describe, it, expect } from 'vitest';
import zh from '../i18n/zh.json';
import en from '../i18n/en.json';

// 递归收集叶子节点 key（数组视为叶子，不展开下标）
function flatKeys(obj: unknown, prefix = ''): string[] {
  if (obj !== null && typeof obj === 'object' && !Array.isArray(obj)) {
    return Object.entries(obj as Record<string, unknown>).flatMap(([k, v]) =>
      flatKeys(v, prefix ? `${prefix}.${k}` : k)
    );
  }
  return [prefix];
}

// 提取 i18n 插值占位符 {{var}} 集合
function placeholders(value: unknown): string[] {
  return typeof value === 'string'
    ? (value.match(/\{\{\s*(\w+)\s*\}\}/g) ?? []).sort()
    : [];
}

function valueAtPath(obj: unknown, path: string): unknown {
  return path
    .split('.')
    .reduce<unknown>(
      (acc, seg) => (acc !== null && typeof acc === 'object' ? (acc as Record<string, unknown>)[seg] : undefined),
      obj
    );
}

const zhKeys = flatKeys(zh).sort();
const enKeys = flatKeys(en).sort();

describe('i18n zh/en 资源一致性', () => {
  it('en 与 zh 的 key 集合完全一致（无缺失/多余）', () => {
    const missingInEn = zhKeys.filter((k) => !enKeys.includes(k));
    const missingInZh = enKeys.filter((k) => !zhKeys.includes(k));
    expect(missingInEn).toEqual([]);
    expect(missingInZh).toEqual([]);
    expect(zhKeys).toEqual(enKeys);
  });

  it('同一 key 的 {{插值占位符}} 在两种语言下一致（防止渲染时变量缺失）', () => {
    const drift: { key: string; zh: string[]; en: string[] }[] = [];
    for (const key of zhKeys) {
      const a = placeholders(valueAtPath(zh, key));
      const b = placeholders(valueAtPath(en, key));
      if (a.join('|') !== b.join('|')) drift.push({ key, zh: a, en: b });
    }
    expect(drift).toEqual([]);
  });

  it('同一 key 不会一侧是文本、另一侧是对象/数组（结构漂移）', () => {
    const typeMismatch = zhKeys.filter((key) => {
      const a = valueAtPath(zh, key);
      const b = valueAtPath(en, key);
      return typeof a !== typeof b;
    });
    expect(typeMismatch).toEqual([]);
  });
});
