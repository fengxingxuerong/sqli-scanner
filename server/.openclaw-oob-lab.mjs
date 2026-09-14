import { initDb, createOobLabApp } from 'file:///D:/projects/sqli-scanner/e2e/oob-real-lab/lab-app.mjs';
await initDb();
const { app } = createOobLabApp({ waf: false });
app.listen(8271, '127.0.0.1', () => console.log('oob lab on 8271'));
setInterval(() => {}, 10000);
