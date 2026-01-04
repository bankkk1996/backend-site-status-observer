const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const cors = require("cors");
const { Pool } = require("pg"); // pg client
const { checkWebsite } = require("./utils/checker");

dotenv.config();

const app = express();
const port = process.env.PORT || 3001;


// 2. แก้ไขบรรทัด app.use(cors()) เป็น:
app.use(cors({
  origin: "*", // หรือระบุโดเมนเจาะจง เช่น "https://my-frontend.vercel.app"
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));


app.use(express.json());

// สร้าง pool สำหรับเชื่อมต่อ DB
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // ถ้า Railway ต้องใช้ SSL แบบนี้
  },
});

// ฟังก์ชันตรวจสอบ JWT
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
  try {
    const userResult = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );
    if (userResult.rows.length > 0)
      return res.status(400).json({ message: "User exists" });

    const hash = await bcrypt.hash(password, 10);
    await pool.query("INSERT INTO users (username, password) VALUES ($1, $2)", [
      username,
      hash,
    ]);

    res.json({ message: "Registered" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Login route
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  console.log(44545454)

  try {
    const userResult = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );

    if (userResult.rows.length === 0)
      return res.status(400).json({ message: "User not found!" });

    const user = userResult.rows[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid)
      return res.status(403).json({ message: "Invalid credentials!" });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    // ✅ อัปเดตเวลาล็อกอินล่าสุด
    await pool.query("UPDATE users SET last_login = NOW() WHERE id = $1", [
      user.id,
    ]);

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/information", authenticateToken, async (req, res) => {
  try {
    const userResult = await pool.query(
      "SELECT id, username, last_login FROM users WHERE username=$1",
      [req.user.username]
    );
    if (userResult.rows.length === 0)
      return res.status(404).json({ message: "User not found" });

    res.json(userResult.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.patch("/users/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userResult = await pool.query(
      "SELECT id, email, name, avatar, created_at, last_login FROM users WHERE username=$1",
      [req.user.username]
    );
    if (userResult.rows.length === 0)
      return res.status(404).json({ message: "User not found" });
    const user = userResult.rows[0];
    // เช็คสิทธิ์ ถ้าไม่ใช่เจ้าของหรือ admin ห้ามแก้ไข


    if (user.id !==  parseInt(id)) {
      return res
        .status(403)
        .json({ message: "Permission denied", user: req.user, userDetail: user, id: id });
    }

    // ระบุเฉพาะ field ที่อยู่ใน DB จริง (กัน SQL injection หรือ field แปลก)
    const validFields = ["email", "name", "avatar", "last_login"];
    const updates = [];
    const values = [];

    let index = 1;
    for (const key of validFields) {
      if (req.body[key] !== undefined) {
        updates.push(`${key} = $${index}`);
        values.push(req.body[key]);
        index++;
      }
    }

    if (updates.length === 0) {
      return res.status(400).json({ message: "No valid fields to update" });
    }

    values.push(id); // ID ไปอยู่ท้ายสุด
    const query = `UPDATE users SET ${updates.join(
      ", "
    )} WHERE id = $${index} RETURNING id, email, name, avatar, created_at, last_login`;
    const result = await pool.query(query, values);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Add website
app.post("/website", authenticateToken, async (req, res) => {
  const { name, url } = req.body;
  const now = new Date();

  try {
    const check = await checkWebsite(url);

    await pool.query(
      `INSERT INTO websites (name, url, status, response_time, last_checked, ssl_expired, ssl_expiry_date, domain_expiry_date, uptime)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [
        name,
        url,
        check.status,
        check.responseTime,
        now,
        check.sslExpired,
        check.sslExpiryDate,
        check.domainExpiryDate,
        check.status === "up" ? 1 : 0,
      ]
    );

    await pool.query(
      `INSERT INTO logs (timestamp, action, username) VALUES ($1, $2, $3)`,
      [now, `Add website ${name}`, req.user.username]
    );

    res.json({ message: "Added", result: check });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// Check website status by id
app.post("/website/:id/check", authenticateToken, async (req, res) => {
  const id = parseInt(req.params.id, 10);
  const now = new Date();

  try {
    const siteResult = await pool.query("SELECT * FROM websites WHERE id=$1", [
      id,
    ]);
    if (siteResult.rows.length === 0)
      return res.status(404).json({ message: "Not Found" });

    const site = siteResult.rows[0];
    const check = await checkWebsite(site.url);

    const uptime = site.uptime + (check.status === "up" ? 1 : 0);

    await pool.query(
      `UPDATE websites SET status=$1, response_time=$2, last_checked=$3, ssl_expired=$4, ssl_expiry_date=$5, domain_expiry_date=$6, uptime=$7 WHERE id=$8`,
      [
        check.status,
        check.responseTime,
        now,
        check.sslExpired,
        check.sslExpiryDate,
        check.domainExpiryDate,
        uptime,
        id,
      ]
    );

    await pool.query(
      `INSERT INTO logs (timestamp, action, username) VALUES ($1, $2, $3)`,
      [now, `Check website ${site.name}`, req.user.username]
    );

    const updatedSiteResult = await pool.query(
      "SELECT * FROM websites WHERE id=$1",
      [id]
    );

    res.json(updatedSiteResult.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/websites/check", authenticateToken, async (req, res) => {
  const now = new Date();

  try {
    // ดึงเว็บไซต์ทั้งหมด
    const sitesResult = await pool.query("SELECT * FROM websites");
    const sites = sitesResult.rows;

    if (sites.length === 0) {
      return res.status(404).json({ message: "No websites found" });
    }

    // เช็คทุกเว็บพร้อมกัน
    const results = await Promise.all(
      sites.map(async (site) => {
        const check = await checkWebsite(site.url);
        const uptime = site.uptime + (check.status === "up" ? 1 : 0);

        // อัปเดตสถานะใน DB
        await pool.query(
          `UPDATE websites 
           SET status=$1, response_time=$2, last_checked=$3, ssl_expired=$4, ssl_expiry_date=$5, domain_expiry_date=$6, uptime=$7 
           WHERE id=$8`,
          [
            check.status,
            check.responseTime,
            now,
            check.sslExpired,
            check.sslExpiryDate,
            check.domainExpiryDate,
            uptime,
            site.id,
          ]
        );

        // เพิ่ม log
        await pool.query(
          `INSERT INTO logs (timestamp, action, username) VALUES ($1, $2, $3)`,
          [now, `Check website ${site.name}`, req.user.username]
        );

        return {
          ...site,
          status: check.status,
          response_time: check.responseTime,
          last_checked: now,
          ssl_expired: check.sslExpired,
          ssl_expiry_date: check.sslExpiryDate,
          domain_expiry_date: check.domainExpiryDate,
          uptime,
        };
      })
    );

    res.json(results);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});


// authenticateToken,
// Get all websites
app.get("/websites",  async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM websites Order by name ASC");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

app.patch("/website/:id", async (req, res)=>{
  try {
    const { id } = req.params;
  
    // ระบุเฉพาะ field ที่อยู่ใน DB จริง (กัน SQL injection หรือ field แปลก)
    const validFields = ["name", "url"];
    const updates = [];
    const values = [];

    let index = 1;
    for (const key of validFields) {
      if (req.body[key] !== undefined) {
        updates.push(`${key} = $${index}`);
        values.push(req.body[key]);
        index++;
      }
    }

    if (updates.length === 0) {
      return res.status(400).json({ message: "No valid fields to update" });
    }

    values.push(id); // ID ไปอยู่ท้ายสุด
    const query = `UPDATE websites SET ${updates.join(
      ", "
    )} WHERE id = $${index} RETURNING id, name, url`;
    const result = await pool.query(query, values);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Website not found" });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
})

// Get logs
app.get("/logs", authenticateToken, async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM logs ORDER BY timestamp DESC");
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Server error" });
  }
});

// ถ้าทำงานในเครื่อง Local ให้รัน app.listen ปกติ
if (require.main === module) {
  app.listen(port, () => {
    console.log(`✅ Server running on http://localhost:${port}`);
  });
}

// สิ่งสำคัญ: ต้อง export app เพื่อให้ Vercel นำไปใช้
module.exports = app;