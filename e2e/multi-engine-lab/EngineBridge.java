// ============================================================================
// engine-jdbc.mjs —— Java 引擎（H2 / HSQLDB / Derby）SQL 求值服务
// 用法：java -cp "<jar>;EngineBridge" EngineBridge 会被逐引擎脚本替代；
// 这里是通用桥：从 stdin 读 JSON {sql, engine}，从 stdout 写 JSON 结果。
// 设计：单进程常驻，避免每个 payload 起一次 JVM（启动 ~1s）。
// ============================================================================
import java.sql.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class EngineBridge {
  // 每个引擎一个独立 Connection（内存库），懒加载
  static final Map<String, Connection> POOL = new HashMap<>();
  static final Set<String> INITED = new HashSet<>();

  static Connection open(String engine) throws Exception {
    if (POOL.containsKey(engine)) return POOL.get(engine);
    Connection c;
    switch (engine) {
      case "h2":
        // MODE=MySQL 提高语法兼容面（注释 # 支持）；IGNORECASE 关闭保持语义
        c = DriverManager.getConnection("jdbc:h2:mem:lab;DB_CLOSE_DELAY=-1;MODE=MySQL;DATABASE_TO_LOWER=TRUE", "sa", "");
        break;
      case "hsqldb":
        c = DriverManager.getConnection("jdbc:hsqldb:mem:lab", "SA", "");
        break;
      case "derby":
        c = DriverManager.getConnection("jdbc:derby:memory:lab;create=true", "APP", "APP");
        break;
      default:
        throw new IllegalArgumentException("unknown engine: " + engine);
    }
    POOL.put(engine, c);
    return c;
  }

  static void initSchema(Connection c) throws Exception {
    try (Statement st = c.createStatement()) {
      try { st.execute("DROP TABLE users"); } catch (SQLException ignore) {}
      // 方言适配：INT/VARCHAR 为三引擎共同子集；IDENTITY 省略（内存库无需自增）
      st.execute("CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(64), role VARCHAR(32))");
      for (int i = 1; i <= 5; i++) {
        st.execute(String.format("INSERT INTO users VALUES (%d, 'user%d', 'user')", i, i));
      }
    }
  }

  public static void main(String[] args) throws Exception {
    // JDBC 4+ SPI 自动加载驱动，无需显式 Class.forName（Derby 10.16 的 AutoloadedDriver 走 SPI）
    BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
    PrintStream out = new PrintStream(System.out, true, "UTF-8");
    String line;
    while ((line = in.readLine()) != null) {
      if (line.trim().isEmpty()) continue;
      String result;
      try {
        String[] parts = line.split("\t", 2);
        String engine = parts[0];
        String sql = parts[1];
        Connection c = open(engine);
        if (!INITED.contains(engine)) { initSchema(c); INITED.add(engine); }
        try (Statement st = c.createStatement()) {
          boolean has = st.execute(sql);
          if (has) {
            ResultSet rs = st.getResultSet();
            ResultSetMetaData md = rs.getMetaData();
            StringBuilder sb = new StringBuilder("[");
            int rows = 0;
            while (rs.next() && rows < 20) {
              if (rows++ > 0) sb.append(",");
                sb.append("[");
              for (int i = 1; i <= md.getColumnCount(); i++) {
                if (i > 1) sb.append(",");
                sb.append('"').append(String.valueOf(rs.getObject(i)).replace("\\", "\\\\").replace("\"", "\\\"")).append('"');
              }
              sb.append("]");
            }
            sb.append("]");
            result = "{\"ok\":true,\"rows\":" + sb + "}";
          } else {
            result = "{\"ok\":true,\"rows\":[]}";
          }
        }
      } catch (SQLException e) {
        result = "{\"ok\":false,\"error\":\"" + e.getMessage().replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", " ") + "\"}";
      } catch (Exception e) {
        result = "{\"ok\":false,\"error\":\"" + String.valueOf(e.getMessage()).replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ").replace("\r", " ") + "\"}";
      }
      out.println(result);
      out.flush();
    }
  }
}
