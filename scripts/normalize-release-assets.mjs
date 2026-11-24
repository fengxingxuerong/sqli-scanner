import { readdirSync, renameSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export function normalizeReleaseAssets(root, version) {
  if (!/^[A-Za-z0-9._-]+$/.test(String(version || ''))) {
    throw new Error(`非法 Release 版本号：${version}`);
  }
  const assets = join(root, 'release-assets');
  const exes = readdirSync(assets, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith('.exe'))
    .map((e) => join(e.parentPath || e.path, e.name));
  if (exes.length !== 1) {
    throw new Error(`Release 安装包数量应为 1，实得 ${exes.length}`);
  }
  const target = join(assets, `sqli-scanner-${version}-x64-setup.exe`);
  renameSync(exes[0], target);
  return relative(root, target).replace(/\\/g, '/');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const root = process.argv[2] || '.';
  const version = process.argv[3] || String(process.env.GITHUB_REF_NAME || '').replace(/^v/, '');
  console.log(normalizeReleaseAssets(root, version));
}
