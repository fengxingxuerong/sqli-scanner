// Fix quote conflicts in payloads.js new DBMS blocks
import { readFileSync, writeFileSync } from 'fs';
import { execSync } from 'child_process';

const path = 'D:/projects/sqli-scanner/server/src/engine/payloads.js';
let src = readFileSync(path, 'utf8');

function fix(oldText, newText) {
  const oldCRLF = oldText.replace(/\n/g, '\r\n');
  if (src.includes(oldCRLF)) {
    src = src.replace(oldCRLF, newText.replace(/\n/g, '\r\n'));
    console.log('✓ fixed:', oldText.slice(0, 50));
    return true;
  }
  console.log('✗ NOT FOUND:', oldText.slice(0, 50));
  return false;
}

// HSQLDB union quote variant (line 495) — outer single-quote closes early at 'HSQLDB'
fix(
  `    '{ORIG}" UNION SELECT {NUM},'HSQLDB' FROM (VALUES(0)) t-- -',`,
  `    "{ORIG}\\" UNION SELECT {NUM},'HSQLDB' FROM (VALUES(0)) t-- -",`
);

// HSQLDB error quote variant (line 499)
fix(
  `    '{ORIG}" AND 1=CAST((SELECT 'a' FROM (VALUES(0)) t) AS INTEGER)-- -',`,
  `    "{ORIG}\\" AND 1=CAST((SELECT 'a' FROM (VALUES(0)) t) AS INTEGER)-- -",`
);

// Derby union quote variant (line 520)
fix(
  `    '{ORIG}" UNION SELECT {NUM},'DERBY' FROM SYSIBM.SYSDUMMY1-- -',`,
  `    "{ORIG}\\" UNION SELECT {NUM},'DERBY' FROM SYSIBM.SYSDUMMY1-- -",`
);

// MonetDB error quote variant (line 545)
fix(
  `    '{ORIG}" AND 1=CAST((SELECT 'a' FROM sys.version) AS INTEGER)-- -',`,
  `    "{ORIG}\\" AND 1=CAST((SELECT 'a' FROM sys.version) AS INTEGER)-- -",`
);

writeFileSync(path, src, 'utf8');
try {
  execSync(`node -c "${path}"`, { encoding: 'utf8', stdio: 'pipe' });
  console.log('✅ Syntax verification passed!');
} catch (e) {
  console.log('❌ Syntax error');
  process.exit(1);
}