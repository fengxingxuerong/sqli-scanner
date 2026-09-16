// fix-eslint.mjs — 修复子代理引入的 unused import
import fs from 'node:fs';

const fixes = [
  { file: 'e2e/acceptance.mjs', pattern: /import \{ existsSync, rmSync \} from 'node:fs';\n?/, replace: '' },
  { file: 'e2e/multi-engine-lab/lab-app.mjs', pattern: /import \{ resolve \} from 'node:path';\n?/, replace: '' },
  { file: 'e2e/multi-engine-lab/verify.mjs', pattern: /const require = createRequire\(import\.meta\.url\);\n?/, replace: '' },
  { file: 'e2e/ntlm-lab/verify.mjs', pattern: /let req;\n?/, replace: '' },
  { file: 'e2e/ntlm-lab/verify.mjs', pattern: /\}, \(res\) => \{\n      reject\(new Error\('HTTP error'\)\); \},/, replace: '}, (res) => {\n      console.error(\'HTTP error\'); },' },
  { file: 'e2e/oob-real-lab/dns-engine-verify.mjs', pattern: /import express from 'express';\n?/, replace: '' },
  { file: 'e2e/oob-real-lab/verify.mjs', pattern: /const require = createRequire\(import\.meta\.url\);\n?/, replace: '' },
  { file: 'e2e/redteam-lab/lab-app.mjs', pattern: /    const rows = result\.rows \|\| result;\n?/, replace: '' },
  { file: 'e2e/redteam-lab/redteam-death-diag.mjs', pattern: /    let m;\n?/, replace: '' },
  { file: 'e2e/redteam-lab/report.mjs', pattern: /    const FP1 = \{ count: 0 \}, FPSM = \{ count: 0 \};\n?/, replace: '' },
];

for (const f of fixes) {
  if (!fs.existsSync(f.file)) { console.log('not found:', f.file); continue; }
  let s = fs.readFileSync(f.file, 'utf8');
  const before = s;
  s = s.replace(f.pattern, f.replace);
  if (s !== before) {
    fs.writeFileSync(f.file, s);
    console.log('fixed:', f.file);
  } else {
    console.log('no match:', f.file);
  }
}
console.log('done');