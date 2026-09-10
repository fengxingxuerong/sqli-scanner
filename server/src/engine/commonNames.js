// ============================================================================
// commonNames.js —— 常见表名 / 列名字典（对标 sqlmap --common-tables / --common-columns）
//
// 用途：当 information_schema 不可用时（被 WAF 拦截 / 数据库账号权限不足 /
// 目标为不支持 information_schema 的库），仍要继续枚举表与列的**唯一出路**。
// 字典按「出现概率从高到低」排列——命中即早停的价值在于请求数，顺序不要随意打乱。
// ============================================================================

// 常见表名（按实战命中率排序：CMS/后台/业务系统高频表在前）
export const COMMON_TABLES = [
  // 账号与权限
  'users', 'user', 'admin', 'administrator', 'admins', 'members', 'member',
  'accounts', 'account', 'account_user', 'sys_user', 'sys_users', 'system_user',
  'user_info', 'userinfo', 'user_data', 'user_account', 'login', 'login_log',
  'user_role', 'roles', 'role', 'permissions', 'permission', 'groups', 'group',
  'auth_user', 'auth_users', 'password', 'passwords', 'credentials',
  // 业务主表
  'orders', 'order', 'order_items', 'orderinfo', 'order_info', 'carts', 'cart',
  'products', 'product', 'goods', 'items', 'item', 'category', 'categories',
  'customers', 'customer', 'clients', 'client', 'suppliers', 'supplier',
  'payments', 'payment', 'transactions', 'transaction', 'invoices', 'invoice',
  // 内容与配置
  'articles', 'article', 'posts', 'post', 'news', 'blogs', 'blog', 'pages', 'page',
  'comments', 'comment', 'contents', 'content', 'messages', 'message',
  'config', 'configs', 'configuration', 'settings', 'setting', 'options', 'option',
  'sys_config', 'system_config', 'sys_configs', 'params', 'parameters',
  'attachments', 'files', 'file', 'uploads', 'upload', 'images', 'image',
  'logs', 'log', 'sys_log', 'operation_log', 'audit_log', 'history',
  'sessions', 'session', 'tokens', 'token', 'api_keys', 'keys', 'key',
  'dictionary', 'dict', 'dict_data', 'sys_dict', 'regions', 'areas', 'dept', 'department',
  // 其它常见
  'notice', 'notices', 'announcement', 'announcements', 'feedback', 'address',
  'addresses', 'coupons', 'coupon', 'statistics', 'stats', 'counter', 'visit',
  'visits', 'tags', 'tag', 'links', 'link', 'menu', 'menus', 'news_category',
];

// 常见列名（按实战命中率排序）
export const COMMON_COLUMNS = [
  // 主键与标识
  'id', 'uid', 'user_id', 'userid', 'user_name', 'username', 'user_pass',
  'password', 'passwd', 'pass', 'pwd', 'salt', 'hash', 'token', 'access_token',
  'refresh_token', 'session_id', 'sessionid', 'key', 'api_key', 'secret',
  // 身份与联系
  'name', 'fullname', 'full_name', 'realname', 'real_name', 'nickname', 'nick',
  'first_name', 'last_name', 'display_name', 'title', 'gender', 'sex', 'age',
  'birthday', 'birth', 'email', 'mail', 'email_address', 'phone', 'mobile',
  'telephone', 'tel', 'phone_number', 'address', 'addr', 'city', 'province',
  'country', 'zip', 'postcode', 'postal_code', 'avatar', 'photo', 'picture',
  // 状态与角色
  'status', 'state', 'enabled', 'disabled', 'active', 'is_active', 'deleted',
  'is_deleted', 'verified', 'is_admin', 'is_super', 'role', 'role_id', 'roles',
  'type', 'user_type', 'level', 'rank', 'group_id', 'permissions', 'is_dba',
  // 时间戳（拖库时常需要判断数据新鲜度）
  'created_at', 'create_time', 'created', 'createdate', 'create_date', 'ctime',
  'updated_at', 'update_time', 'updated', 'modify_time', 'mtime', 'last_login',
  'login_time', 'login_at', 'expires_at', 'expire_time', 'deleted_at', 'deleted_time',
  // 业务字段
  'content', 'body', 'text', 'description', 'desc', 'remark', 'note', 'notes',
  'comment', 'message', 'subject', 'summary', 'keyword', 'keywords', 'tags',
  'category', 'category_id', 'cat_id', 'parent_id', 'pid', 'sort', 'order',
  'price', 'amount', 'total', 'count', 'qty', 'quantity', 'number', 'num',
  'money', 'balance', 'score', 'point', 'points', 'weight', 'size', 'color',
  'image', 'img', 'url', 'link', 'path', 'file', 'filename', 'file_path',
  'ip', 'ip_address', 'user_agent', 'ua', 'referer', 'referrer', 'host',
];

// 探测用的「必然不存在」对照名（用于区分「表不存在」与「通道不可用」）
export const NONEXISTENT_PROBE = '__sqli_scanner_missing_probe__';
