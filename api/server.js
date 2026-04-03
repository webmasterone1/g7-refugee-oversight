const express = require("express");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
app.use(express.json());

// 🔒 HOST LOCK
app.use((req, res, next) => {
  const allowedHosts = ["localhost:3000", "127.0.0.1:3000"];
  if (!allowedHosts.includes(req.headers.host)) {
    return res.status(403).send("Host blocked");
  }
  next();
});

// 🔐 SECURITY
function secure(req, res, next) {
  const apiKey = req.headers["x-api-key"];
  const signature = req.headers["x-signature"];
  const timestamp = req.headers["x-timestamp"];

  if (!apiKey || !signature || !timestamp) {
    return res.status(403).json({ error: "Missing headers" });
  }

  const payload = `${req.method}:${req.originalUrl}:${timestamp}`;

  const expected = crypto
    .createHmac("sha256", process.env.HMAC_SECRET || "dev_secret")
    .update(payload)
    .digest("hex");

  if (apiKey !== (process.env.ROOT_KEY || "dev_key") || signature !== expected) {
    return res.status(403).json({ error: "Unauthorized" });
  }

  next();
}

// 🧪 HEALTH CHECK
app.get("/", (req, res) => {
  res.send("api running");
});

// 📡 INDEX CONTROL
app.post("/api/index/reindex", secure, (req, res) => {
  res.json({ status: "reindex triggered" });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Running on ${PORT}`);
});
