import 'dotenv/config';
import { createApp } from './app.js';
import { initializeDatabase } from './db.js';

await initializeDatabase();
const app = createApp();
app.listen(process.env.PORT || 4000, () => console.log('Fixify API on :' + (process.env.PORT || 4000)));
