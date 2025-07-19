const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const cors = require("cors");
const { Low } = require("lowdb");
const { JSONFile } = require("lowdb/node");
const fs = require("fs");
const { checkWebsite } = require("./utils/checker");

dotenv.config();

const app = express();
const port = process.env.port || 3001;

app.use(cors());
app.use(express.json());

// ✅ ห่อด้วย async IIFE (Immediately Invoked Function Expression)
(async () => {
  const db = new Low(new JSONFile("db.json"), { websites: [], logs: [] });
  const usersDb = new Low(new JSONFile("users.json"), { users: [] });
  await db.read();
  db.data ||= { websites: [], logs: [] };

  await usersDb.read();
  usersDb.data ||= { users: [] };

  const authenticateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader?.split(" ")[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  };

  // Register route
  app.post("/register", async (req, res) => {
    const { username, password } = req.body;
    const existing = usersDb.data.users.find((u) => u.username === username);
    if (existing) return res.status(400).json({ message: "User exists" });

    const hash = await bcrypt.hash(password, 10);
    usersDb.data.users.push({ id: Date.now(), username, password: hash });
    await usersDb.write();
    res.json({ message: "Registered" });
  });

  // Login route
  app.post("/login", async (req, res) => {
    const { username, password } = req.body;
    const user = usersDb.data.users.find((u) => u.username === username);
    if (!user) return res.status(400).json({ message: "User not found!" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(403).json({ message: "Invalid credentials!" });

    const token = jwt.sign(
      { username: user.username },
      process.env.JWT_SECRET,
      {
        expiresIn: "1d",
      }
    );

    res.json({ token });
  });

  app.post("/website", authenticateToken, async (req, res) => {
    const { id, name, url } = req.body;
    const check = await checkWebsite(url);
    const now = new Date().toISOString();

    db.data.websites.push({
      id,
      name,
      url,
      status: check.status,
      responseTime: check.responseTime,
      lastchecked: now,
      sslExpired: check.sslExpired,
      sslExpiryDate: check.sslExpiryDate,
      domainExpiryDate: check.domainExpiryDate,
      uptime: check.status === "up" ? 1 : 0,
    });

    db.data.logs.push({
      time: now,
      action: `Add website ${name}`,
      user: req.user.username,
    });

    await db.write();
    res.json({ message: "Added", result: check });
  });

  app.post("/website/:id/check", authenticateToken, async (req, res) => {
    const { id } = req.params;

    const site = db.data.websites.find((w) => w.id === parseInt(id, 10));
    if (!site) return res.status(404).json({ message: "Not Found" });

    const check = await checkWebsite(site.url);
    site.status = check.status;
    site.responseTime = check.responseTime;
    site.lastchecked = new Date().toISOString();
    site.sslExpired = check.sslExpired; // แก้ไขตรงนี้
    site.sslExpiryDate = check.sslExpiryDate; // เก็บวันที่หมดอายุ SSL
    site.domainExpiryDate = check.domainExpiryDate; // เก็บวันที่หมดอายุโดเมน (ถ้ามี)
    site.uptime += check.status === "up" ? 1 : 0;

    db.data.logs.push({
      time: new Date().toISOString(),
      action: `Check website ${site.name}`,
      user: req.user.username,
    });

    await db.write();
    res.json(site);
  });

  app.get("/websites", authenticateToken, async (req, res) => {
    res.json(db.data.websites);
  });

  app.get("/logs", authenticateToken, async (req, res) => {
    res.json(db.data.logs);
  });

  app.listen(port, () =>
    console.log(`✅ Server running on http://localhost:${port}`)
  );
})();
