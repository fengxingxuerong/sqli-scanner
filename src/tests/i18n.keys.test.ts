import { describe, expect, it } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';

const SRC = path.resolve(process.cwd(), 'src');
const TESTS_DIR = path.join(SRC, 'tests');
const LOCALES = ['zh', 'en'] as const;

function sourceFiles(dir: string): string[] {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return full === TESTS_DIR ? [] : sourceFiles(full);
    return /\.(tsx?|jsx?)$/.test(entry.name) ? [full] : [];
  });
}

function tKeys(): string[] {
  const keys: string[] = [];
  for (const file of sourceFiles(SRC)) {
    const text = fs.readFileSync(file, 'utf8');
    for (const match of text.matchAll(/\bt\(\s*['"]([^'"]+)['"]/g)) keys.push(match[1]);
  }
  return [...new Set(keys)];
}

function hasKey(dict: unknown, dotted: string): boolean {
  return dotted.split('.').every((part) => {
    const next = (dict as Record<string, unknown> | undefined)?.[part];
    if (next === undefined) return false;
    dict = next;
    return true;
  });
}

describe('i18n 字典完整性', () => {
  it('src 里每个 t() 键都在 zh/en 字典里（缺键会直接显示原始键名）', () => {
    const keys = tKeys();
    expect(keys.length).toBeGreaterThan(0);

    const missing: string[] = [];
    for (const lang of LOCALES) {
      const dict = JSON.parse(fs.readFileSync(path.join(SRC, 'i18n', `${lang}.json`), 'utf8')) as unknown;
      for (const key of keys) if (!hasKey(dict, key)) missing.push(`${lang}:${key}`);
    }
    expect(missing, `缺失的翻译键：\n${missing.join('\n')}`).toEqual([]);
  });
});
