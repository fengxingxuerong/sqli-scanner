# WAF 绕过验证报告（HTTP 实测）

> 生成时间：2026-09-04T16:08:17.228Z
> 测试插件：225 个
> 测试 payload：14 个
> WAF 场景：3 个

---

## 汇总对比

| WAF 场景 | 有效插件 | Top-3 |
|---------|---------|-------|
| ModSecurity CRS (OWASP) | 107/225 | base64encode(100%), charunicodeencode(100%), charunicodeescape(100%) |
| Cloudflare WAF (simulated) | 25/225 | base64encode(100%), charunicodeescape(100%), hexentities(100%) |
| All-in-One (最严格) | 20/225 | base64encode(100%), charunicodeescape(100%), encode2hex(100%) |

## 各场景详情

### ModSecurity CRS (OWASP)

| 排名 | 插件名 | 绕过率 | 绕过/拦截 |
|------|--------|--------|----------|
| 1 | base64encode | 100% | 14/14 |
| 2 | charunicodeencode | 100% | 14/14 |
| 3 | charunicodeescape | 100% | 14/14 |
| 4 | encode2hex | 100% | 14/14 |
| 5 | encode2dec | 100% | 14/14 |
| 6 | encode2oct | 100% | 14/14 |
| 7 | overlongutf8more | 100% | 14/14 |
| 8 | keywordSplit | 50% | 7/14 |
| 9 | space2comment | 43% | 6/14 |
| 10 | charencode | 43% | 6/14 |
| 11 | space2plus | 43% | 6/14 |
| 12 | space2dash | 43% | 6/14 |
| 13 | versionedkeywords | 43% | 6/14 |
| 14 | percentage | 43% | 6/14 |
| 15 | modsecurityversioned | 43% | 6/14 |
| 16 | modsecurityzeroversioned | 43% | 6/14 |
| 17 | chardoubleencode | 43% | 6/14 |
| 18 | randomwhitespace | 43% | 6/14 |
| 19 | bluecoat | 43% | 6/14 |
| 20 | commentbeforewhitespace | 43% | 6/14 |

### Cloudflare WAF (simulated)

| 排名 | 插件名 | 绕过率 | 绕过/拦截 |
|------|--------|--------|----------|
| 1 | base64encode | 100% | 14/14 |
| 2 | charunicodeescape | 100% | 14/14 |
| 3 | hexentities | 100% | 14/14 |
| 4 | decentities | 100% | 14/14 |
| 5 | encode2hex | 100% | 14/14 |
| 6 | encode2dec | 100% | 14/14 |
| 7 | encode2oct | 100% | 14/14 |
| 8 | overlongutf8more | 100% | 14/14 |
| 9 | htmlencode | 50% | 7/14 |
| 10 | charencode | 43% | 6/14 |
| 11 | space2plus | 43% | 6/14 |
| 12 | space2dash | 43% | 6/14 |
| 13 | chardoubleencode | 43% | 6/14 |
| 14 | randomwhitespace | 43% | 6/14 |
| 15 | bluecoat | 43% | 6/14 |
| 16 | space2mssqlblank | 43% | 6/14 |
| 17 | space2mssqlhash | 43% | 6/14 |
| 18 | space2mysqlblank | 43% | 6/14 |
| 19 | space2mysqldash | 43% | 6/14 |
| 20 | space2randomblank | 43% | 6/14 |

### All-in-One (最严格)

| 排名 | 插件名 | 绕过率 | 绕过/拦截 |
|------|--------|--------|----------|
| 1 | base64encode | 100% | 14/14 |
| 2 | charunicodeescape | 100% | 14/14 |
| 3 | encode2hex | 100% | 14/14 |
| 4 | encode2dec | 100% | 14/14 |
| 5 | encode2oct | 100% | 14/14 |
| 6 | overlongutf8more | 100% | 14/14 |
| 7 | charencode | 29% | 4/14 |
| 8 | chardoubleencode | 29% | 4/14 |
| 9 | bluecoat | 29% | 4/14 |
| 10 | space2plus | 7% | 1/14 |
| 11 | space2dash | 7% | 1/14 |
| 12 | randomwhitespace | 7% | 1/14 |
| 13 | space2mssqlblank | 7% | 1/14 |
| 14 | space2mssqlhash | 7% | 1/14 |
| 15 | space2mysqlblank | 7% | 1/14 |
| 16 | space2mysqldash | 7% | 1/14 |
| 17 | space2randomblank | 7% | 1/14 |
| 18 | space2nbsp | 7% | 1/14 |
| 19 | space2blank | 7% | 1/14 |
| 20 | safedog | 7% | 1/14 |

## 最佳通用插件（跨场景）

| 插件名 | 平均绕过率 | 各场景 |
|--------|-----------|-------|
| base64encode | 100% | modsecurity_crs=100%, cloudflare_waf=100%, all_in_one=100% |
| charunicodeescape | 100% | modsecurity_crs=100%, cloudflare_waf=100%, all_in_one=100% |
| encode2hex | 100% | modsecurity_crs=100%, cloudflare_waf=100%, all_in_one=100% |
| encode2dec | 100% | modsecurity_crs=100%, cloudflare_waf=100%, all_in_one=100% |
| encode2oct | 100% | modsecurity_crs=100%, cloudflare_waf=100%, all_in_one=100% |
| overlongutf8more | 100% | modsecurity_crs=100%, cloudflare_waf=100%, all_in_one=100% |
| charencode | 38% | modsecurity_crs=43%, cloudflare_waf=43%, all_in_one=29% |
| chardoubleencode | 38% | modsecurity_crs=43%, cloudflare_waf=43%, all_in_one=29% |
| bluecoat | 38% | modsecurity_crs=43%, cloudflare_waf=43%, all_in_one=29% |
| charunicodeencode | 33% | modsecurity_crs=100%, cloudflare_waf=0%, all_in_one=0% |
| hexentities | 33% | modsecurity_crs=0%, cloudflare_waf=100%, all_in_one=0% |
| decentities | 33% | modsecurity_crs=0%, cloudflare_waf=100%, all_in_one=0% |
| space2plus | 31% | modsecurity_crs=43%, cloudflare_waf=43%, all_in_one=7% |
| space2dash | 31% | modsecurity_crs=43%, cloudflare_waf=43%, all_in_one=7% |
| randomwhitespace | 31% | modsecurity_crs=43%, cloudflare_waf=43%, all_in_one=7% |
