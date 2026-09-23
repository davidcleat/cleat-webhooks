// Run: CLEAT_WEBHOOK_SECRET=whsec_... node server.js
import { createApp, WEBHOOK_PATH } from "./app.js";

const port = Number(process.env.PORT ?? 3000);

createApp().listen(port, () => {
  console.log(`listening on http://localhost:${port}${WEBHOOK_PATH}`);
  if (!process.env.CLEAT_WEBHOOK_SECRET) {
    console.warn("CLEAT_WEBHOOK_SECRET is not set: every delivery will be answered 500");
  }
});
