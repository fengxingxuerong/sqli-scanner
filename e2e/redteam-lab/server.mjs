import { createLabApp } from './lab-app.mjs';
const port = Number(process.env.REDTEAM_LAB_PORT) || 8231;
const app = await createLabApp();
app.listen(port, () => console.log(`[redteam-lab] http://127.0.0.1:${port}`));
