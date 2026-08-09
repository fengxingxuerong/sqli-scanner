// 空格 -> 内联注释 /**/，绕过空格过滤（类名 space2comment）
// 导出 camelCase 常量 space2comment，name 唯一对应 config.wafEvasion.tamper.plugins 字符串。
export const space2comment = {
  name: 'space2comment',
  description: '将空格替换为内联注释 /**/，绕过空格过滤',
  compat: { conflicts: ['space2plus', 'randomcomments'] },
  /**
   * @param {string} payload 待混淆的注入串
   * @param {object} ctx 检测上下文（透传，便于高级插件按 dbms 决策）
   * @returns {string}
   */
  transform(payload, ctx) {
    return payload.replace(/ /g, '/**/');
  },
};

export default space2comment;
