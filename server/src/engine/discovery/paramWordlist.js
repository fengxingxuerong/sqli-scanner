// ============================================================================
// paramWordlist.js — 参数挖掘内置字典（paramMine 消费，纯数据）
//
// 竞品对标（2026-10-02 吸收 Arjun 的参数发现思路）：Arjun 自带 2.6 万条字典跑全量
// 分组探测；本工具是 SQL 注入扫描器而非专职参数发现器，字典只求覆盖常见命名，
// 取 top ~260 条高频 Web 参数名（小写字母/数字/下划线，全载体安全：query/urlencoded
// 序列化无需转义）。刻意不内置超大字典：挖掘的请求预算 maxRequests 会先于字典
// 耗尽，大字典只会白白稀释预算，想扩量的用户应先跑专职工具（Arjun/x8）再回填目标。
// ============================================================================

export const PARAM_WORDLIST = Object.freeze([
  // 标识符类
  'id', 'ids', 'uid', 'gid', 'pid', 'cid', 'tid', 'fid', 'sid', 'aid',
  'user_id', 'userid', 'user', 'username', 'user_name', 'usr', 'login', 'log',
  'account', 'acct', 'member', 'member_id', 'profile_id', 'owner', 'author',
  'admin', 'customer', 'customer_id', 'employee', 'emp_id', 'staff',
  'product_id', 'product', 'item', 'item_id', 'item_id2', 'sku', 'article',
  'article_id', 'post', 'post_id', 'page_id', 'postid', 'news_id', 'topic',
  'topic_id', 'thread', 'thread_id', 'forum', 'board', 'category_id', 'cat_id',
  'order_id', 'orderid', 'invoice', 'invoice_id', 'ref', 'reference', 'doc',
  'doc_id', 'file_id', 'record', 'record_id', 'entry', 'entry_id',
  // 搜索/查询类
  'q', 's', 'search', 'query', 'keyword', 'keywords', 'kw', 'term', 'find',
  'filter', 'filters', 'where', 'condition', 'expression', 'pattern', 'match',
  // 分页/排序类
  'page', 'p', 'per_page', 'perpage', 'pagesize', 'page_size', 'limit', 'lim',
  'offset', 'start', 'count', 'size', 'rows', 'total', 'max', 'min', 'range',
  'sort', 'order', 'orderby', 'order_by', 'sortby', 'sort_by', 'dir', 'direction',
  // 分类/枚举类
  'cat', 'category', 'type', 'types', 'tag', 'tags', 'label', 'group', 'group_id',
  'class', 'kind', 'style', 'mode', 'action', 'act', 'op', 'operation', 'do',
  'cmd', 'command', 'exec', 'run', 'func', 'function', 'method', 'module',
  'controller', 'task', 'job', 'view', 'viewtype', 'template', 'layout', 'theme',
  // 时间/数值类
  'year', 'month', 'day', 'date', 'time', 'from', 'to', 'until', 'since',
  'timestamp', 'ts', 'created', 'updated', 'modified', 'start_date', 'end_date',
  'price', 'amount', 'qty', 'quantity', 'total_price', 'discount', 'cost',
  'currency', 'value', 'val', 'num', 'number', 'no', 'code',
  // 文件/路径类
  'file', 'filename', 'path', 'dir', 'directory', 'folder', 'download',
  'upload', 'img', 'image', 'images', 'photo', 'pic', 'thumb', 'thumbnail',
  'attachment', 'media', 'video', 'audio', 'src', 'url', 'link', 'href',
  'redirect', 'redirect_uri', 'redirect_url', 'return', 'returnurl', 'return_to',
  'next', 'callback', 'continue', 'dest', 'destination', 'target', 'goto', 'back',
  // 认证/会话类
  'email', 'mail', 'e_mail', 'password', 'passwd', 'pass', 'pwd', 'token',
  'access_token', 'auth', 'auth_token', 'api_key', 'apikey', 'api', 'secret',
  'session', 'sessionid', 'session_id', 'sid', 'jsessionid', 'phpsessid',
  'csrf', 'csrftoken', 'csrf_token', 'nonce', 'state', 'oauth', 'sso',
  // 国际化/本地化类
  'lang', 'language', 'locale', 'country', 'region', 'city', 'zone', 'tz',
  'timezone', 'lat', 'lon', 'lng', 'latitude', 'longitude', 'address', 'zip',
  'zipcode', 'postal', 'phone', 'mobile', 'tel', 'fax',
  // 状态/配置类
  'status', 'state2', 'enabled', 'active', 'visible', 'published', 'approved',
  'role', 'permission', 'privilege', 'level', 'priority', 'flag', 'options',
  'format', 'output', 'encoding', 'charset', 'version', 'ver', 'v', 'rev',
  'debug', 'test', 'dev', 'staging', 'verbose', 'trace', 'log', 'log_level',
  'host', 'domain', 'site', 'server', 'ip', 'port', 'db', 'database', 'table',
  'column', 'col', 'field', 'fields', 'select', 'schema', 'name', 'title',
  'description', 'desc', 'content', 'body', 'text', 'comment', 'message',
  'msg', 'note', 'subject', 'summary', 'excerpt', 'data', 'payload', 'params',
  'input', 'output_format', 'render', 'display', 'show', 'hide',
]);

/** 供挖掘阶段排除的哨兵参数名（探测标记自身，绝不作为候选） */
export const MINE_CANARY = '__zn_canary__';
