// Import required modules
const express = require("express");
const mysql = require("mysql2/promise"); // Use promise-based API
const cors = require("cors");
const helmet = require("helmet");
const { body, validationResult } = require("express-validator");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const fs = require("fs").promises;
const bcrypt = require("bcrypt");
const WebSocket = require("ws");
const multer = require('multer');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const { OpenAI } = require('openai');
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const crypto = require("crypto");
const schedule = require('node-schedule');
const http = require('http'); // Added for WebSocket integration
const path = require('path'); // Added for file paths

require("dotenv").config();

// Initialize OpenAI client
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Configure multer for in-memory file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage });

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "MY_SECRET_TOKEN";

// MySQL Connection Pool
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'job_portal',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Helper function for MySQL queries
const query = async (sql, params) => {
  const [rows] = await pool.query(sql, params);
  return rows;
};

const generateNonce = (req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString("base64");
  next();
};

// Initialize Express app
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(generateNonce);
app.use(cors());
app.use(helmet());
app.use(morgan("combined"));

// Create HTTP server for WebSocket
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Backend WebSocket handling
wss.on('connection', (ws, req) => {
  console.log("New WebSocket connection");
  const token = req.headers.authorization?.split(' ')[1];

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (!err) {
        ws.userPhone = user.phone;
      }
    });
  }

  ws.on('message', (message) => {
    const data = JSON.parse(message);
    switch (data.type) {
      case 'register_phone':
        ws.userPhone = data.phone;
        break;
      case 'direct_message':
        handleDirectMessage(data);
        break;
    }
  });
});

// Handle direct messages
function handleDirectMessage(data) {
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN &&
      (client.userPhone === data.recipient_phone || client.userPhone === data.sender_phone)) {
      client.send(JSON.stringify({
        type: 'direct_message',
        message: data
      }));
    }
  });
}

// Configure CORS for external access
const corsOptions = {
  origin: "*",
};
app.use(cors(corsOptions));

const getClientIp = (req) => {
  const ip = req.headers["x-forwarded-for"] || req.connection.remoteAddress;
  return ip.split(",")[0].trim();
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: "Token required" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
};

const authorizeAdmin = (req, res, next) => {
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
};

// Configure passport with Google strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:5000/api/auth/google/callback",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const [existingUser] = await query("SELECT * FROM users WHERE google_id = ?", [profile.id]);

        if (existingUser.length) {
          await query("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE google_id = ?", [profile.id]);
          return done(null, existingUser[0]);
        }

        const [newUser] = await query(
          `INSERT INTO users (
            google_id, 
            display_name, 
            email, 
            photo_url
          ) VALUES (?, ?, ?, ?)`,
          [profile.id, profile.displayName, profile.emails[0].value, profile.photos[0].value]
        );
        const [insertedUser] = await query("SELECT * FROM users WHERE id = ?", [newUser.insertId]);
        return done(null, insertedUser[0]);
      } catch (error) {
        return done(error, null);
      }
    },
  ),
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const [user] = await query("SELECT * FROM users WHERE id = ?", [id]);
    done(null, user[0]);
  } catch (error) {
    done(error, null);
  }
});

app.use(passport.initialize());

// Admin registration
app.post(
  "/api/admin/register",
  [
    body("adminname").notEmpty(),
    body("username").notEmpty(),
    body("password").isLength({ min: 6 }),
    body("phone").isMobilePhone(),
    body("admin_image_link").optional().isURL(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { adminname, username, password, phone, admin_image_link } = req.body;
    try {
      const [adminCountResult] = await query("SELECT COUNT(*) AS count FROM admin");
      const adminCount = adminCountResult[0].count;
      const isFirstAdmin = adminCount === 0;

      const [existingAdmin] = await query(
        "SELECT * FROM admin WHERE username = ? OR phone = ?",
        [username, phone]
      );
      if (existingAdmin.length) {
        return res.status(400).json({ error: "Username or phone already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const status = isFirstAdmin ? "approved" : "pending";
      const isApproved = isFirstAdmin ? 1 : 0;
      const createdBy = isFirstAdmin ? null : req.user?.id || null;

      const [insertResult] = await query(
        `INSERT INTO admin (adminname, username, password, phone, admin_image_link, status, is_approved, created_by)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [adminname, username, hashedPassword, phone, admin_image_link || null, status, isApproved, createdBy]
      );

      const adminId = insertResult.insertId;
      const responseData = {
        message: isFirstAdmin ? "First admin registered successfully" : "Registration submitted for approval",
        adminId,
        status,
        is_approved: !!isApproved,
      };

      res.status(201).json(responseData);
    } catch (error) {
      console.error(`Error registering admin: ${error.message}`);
      res.status(500).json({ error: "Registration failed" });
    }
  }
);

// Admin login
app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const [adminRows] = await query("SELECT * FROM admin WHERE username = ?", [username]);

    if (!adminRows.length) {
      return res.status(401).json({ error: "Invalid credentials or Please Register" });
    }

    const admin = adminRows[0];
    const isFirstAdmin = admin.created_by === null && admin.is_approved;

    if (admin.status !== 'approved') {
      return res.status(403).json({ error: "Account pending approval" });
    }

    const passwordMatch = await bcrypt.compare(password, admin.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: "Invalid Password" });
    }

    const token = jwt.sign(
      { id: admin.id, username: admin.username, phone: admin.phone, role: "admin" },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful",
      token,
      admin: {
        adminname: admin.adminname,
        username: admin.username,
        phone: admin.phone,
        admin_image_link: admin.admin_image_link,
        status: admin.status,
        isFirstAdmin
      }
    });
  } catch (error) {
    console.error(`Login error: ${error.message}`);
    res.status(500).json({ error: "Login failed" });
  }
});

// Get pending admins
app.get("/api/admin/pending", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const [pendingAdmins] = await query("SELECT id, adminname, username, phone, admin_image_link, createdAt FROM admin WHERE status = 'pending'");
    res.json(pendingAdmins);
  } catch (error) {
    console.error(`Error fetching pending admins: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve pending admins" });
  }
});

// Approve admin
app.put("/api/admin/approve/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const [checkAdmin] = await query("SELECT * FROM admin WHERE id = ? AND status = 'pending'", [id]);
    if (checkAdmin.length === 0) {
      return res.status(404).json({ error: "Admin not found or already approved" });
    }

    await query("UPDATE admin SET status = 'approved', is_approved = TRUE, created_by = ? WHERE id = ?", [req.user.id, id]);
    const [updatedAdmin] = await query("SELECT * FROM admin WHERE id = ?", [id]);

    res.json({
      message: "Admin approved successfully",
      admin: updatedAdmin[0],
    });
  } catch (error) {
    console.error(`Approval error: ${error.message}`);
    res.status(500).json({ error: "Approval failed" });
  }
});

// Reject admin
app.put("/api/admin/reject/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const [existingAdmin] = await query("SELECT * FROM admin WHERE id = ?", [id]);
    if (existingAdmin.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    await query("DELETE FROM admin WHERE id = ?", [id]);
    res.json({ message: "Admin rejected and removed from the system" });
  } catch (error) {
    console.error(`Rejection error: ${error.message}`);
    res.status(500).json({ error: "Rejection failed" });
  }
});

// Initialize DB and start server
const initializeDbAndServer = async () => {
  try {
    // Create tables
    await query(`
      CREATE TABLE IF NOT EXISTS admin (
        id INT AUTO_INCREMENT PRIMARY KEY,
        adminname VARCHAR(255) NOT NULL,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        phone VARCHAR(20) NOT NULL UNIQUE,
        admin_image_link TEXT,
        is_approved BOOLEAN DEFAULT FALSE,
        status VARCHAR(20) DEFAULT 'pending',
        created_by INT,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES admin(id)
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS job (
        id INT AUTO_INCREMENT PRIMARY KEY,
        companyname VARCHAR(255) NOT NULL,
        title VARCHAR(255) NOT NULL,
        description TEXT NOT NULL,
        apply_link TEXT NOT NULL,
        image_link TEXT NOT NULL,
        url TEXT NOT NULL,
        salary VARCHAR(100) NOT NULL,
        location VARCHAR(255) NOT NULL,
        job_type VARCHAR(100) NOT NULL,
        experience VARCHAR(100) NOT NULL,
        batch VARCHAR(100) NOT NULL,
        job_uploader VARCHAR(255) NOT NULL,
        approved_by INT,
        created_by INT,
        status VARCHAR(20) DEFAULT 'pending',
        advanced_data TEXT,
        createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (approved_by) REFERENCES admin(id),
        FOREIGN KEY (created_by) REFERENCES admin(id)
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS job_viewers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        job_id INT NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_job_ip (job_id, ip_address),
        FOREIGN KEY (job_id) REFERENCES job(id) ON DELETE CASCADE
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS popup_content (
        id INT AUTO_INCREMENT PRIMARY KEY,
        popup_heading TEXT NOT NULL,
        popup_text TEXT NOT NULL,
        popup_link TEXT NOT NULL,
        popup_belowtext TEXT NOT NULL,
        popup_routing_link TEXT NOT NULL,
        created_by INT,
        approved_by INT,
        status VARCHAR(20) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (created_by) REFERENCES admin(id),
        FOREIGN KEY (approved_by) REFERENCES admin(id)
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS chat_rooms (
        id INT AUTO_INCREMENT PRIMARY KEY,
        room_name VARCHAR(255) NOT NULL UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        room_id INT NOT NULL,
        sender_id INT NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (room_id) REFERENCES chat_rooms(id) ON DELETE CASCADE,
        FOREIGN KEY (sender_id) REFERENCES admin(id) ON DELETE CASCADE
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS direct_messages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        sender_phone VARCHAR(20) NOT NULL,
        recipient_phone VARCHAR(20) NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_phone) REFERENCES admin(phone) ON DELETE CASCADE,
        FOREIGN KEY (recipient_phone) REFERENCES admin(phone) ON DELETE CASCADE
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS admin_sessions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id INT,
        start_time TIMESTAMP NOT NULL,
        end_time TIMESTAMP DEFAULT NULL,
        duration INT DEFAULT NULL,
        FOREIGN KEY (admin_id) REFERENCES admin(id) ON DELETE CASCADE
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS monthly_reports (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id INT,
        month INT,
        year INT,
        total_time BIGINT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (admin_id) REFERENCES admin(id) ON DELETE CASCADE
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS job_approval_requests (
        id INT AUTO_INCREMENT PRIMARY KEY,
        job_id INT NOT NULL,
        requester_admin_id INT NOT NULL,
        owner_admin_id INT NOT NULL,
        requester_image TEXT,
        action VARCHAR(10) NOT NULL,
        data JSON,
        status VARCHAR(10) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (job_id) REFERENCES job(id) ON DELETE CASCADE,
        FOREIGN KEY (requester_admin_id) REFERENCES admin(id) ON DELETE CASCADE,
        FOREIGN KEY (owner_admin_id) REFERENCES admin(id) ON DELETE CASCADE
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS job_clicks (
        id INT AUTO_INCREMENT PRIMARY KEY,
        job_id INT NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_job_ip (job_id, ip_address),
        FOREIGN KEY (job_id) REFERENCES job(id) ON DELETE CASCADE
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS comments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        job_id INT NOT NULL,
        user_name TEXT NOT NULL,
        comment_text TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (job_id) REFERENCES job(id) ON DELETE CASCADE
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS resumes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        job_id INT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone VARCHAR(20),
        resume_file LONGBLOB NOT NULL,
        file_type VARCHAR(100) NOT NULL,
        skills TEXT,
        experience TEXT,
        match_percentage FLOAT,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (job_id) REFERENCES job(id)
      )
    `);

    await query(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        google_id VARCHAR(255) NOT NULL UNIQUE,
        display_name VARCHAR(255) NOT NULL,
        email VARCHAR(255) NOT NULL UNIQUE,
        photo_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP NULL
      )
    `);

    // Fixed count queries with proper error handling
    const getTableCount = async (tableName) => {
      try {
        const [result] = await query(`SELECT COUNT(*) as count FROM ${tableName}`);
        return result[0]?.count || 0;
      } catch (error) {
        console.error(`Error counting ${tableName}:`, error.message);
        return 0;
      }
    };
    const popupCount = await getTableCount('popup_content');
    const jobsCount = await getTableCount('job');
    const adminCount = await getTableCount('admin');

    // Check and import initial data
    const [popUpCountResult] = await query("SELECT COUNT(*) as count FROM popup_content");

    if (popupCount === 0) {
      try {
        const popsPath = path.join(__dirname, 'pops.json');
        const data = await fs.readFile(popsPath, "utf8");
        const popList = JSON.parse(data);

        for (const popup_content of popList) {
          await query(
            `INSERT INTO popup_content (popup_heading, popup_text, popup_link, popup_belowtext, popup_routing_link)
             VALUES (?, ?, ?, ?, ?)`,
            [
              popup_content.popup_heading,
              popup_content.popup_text,
              popup_content.popup_link,
              popup_content.popup_belowtext,
              popup_content.popup_routing_link,
            ]
          );
        }
        console.log("Pop Data Imported Successfully");
      } catch (error) {
        console.error("Error reading or processing pops.json:", error.message);
      }
    }

    const [jobsCountResult] = await query("SELECT COUNT(*) as count FROM job");

    if (jobsCount === 0) {
      try {
        const jobsPath = path.join(__dirname, 'jobs.json');
        const data = await fs.readFile(jobsPath, "utf8");
        const jobList = JSON.parse(data);

        for (const job of jobList) {
          await query(
            `INSERT INTO job (companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch, job_uploader)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [
              job.companyname,
              job.title,
              job.description,
              job.apply_link,
              job.image_link,
              job.url,
              job.salary,
              job.location,
              job.job_type,
              job.experience,
              job.batch,
              job.job_uploader,
            ]
          );
        }
        console.log("Job data has been imported successfully.");
      } catch (error) {
        console.error("Error importing job data:", error.message);
      }
    }

    const [adminCountResult] = await query("SELECT COUNT(*) as count FROM admin");

    if (adminCount === 0) {
      try {
        const adminPath = path.join(__dirname, 'admin.json');
        const data = await fs.readFile(adminPath, "utf8");
        const adminList = JSON.parse(data);

        for (const admin of adminList) {
          const hashedPassword = await bcrypt.hash(admin.password, 10);
          await query(
            `INSERT INTO admin (adminname, username, password, phone, admin_image_link)
             VALUES (?, ?, ?, ?, ?)`,
            [admin.adminname, admin.username, hashedPassword, admin.phone, admin.admin_image_link]
          );
        }
        console.log("Admin data has been imported successfully.");
      } catch (error) {
        console.error("Error importing admin data:", error.message);
      }
    }

    // Start server after DB initialization
    server.listen(PORT, () => {
      console.log(`Server is running on http://localhost:${PORT}/`);
    });
  } catch (error) {
    console.error(`Error initializing the database: ${error.message}`);
    process.exit(1);
  }
};

// Get comments for a job
app.get("/api/comments/:jobId", async (req, res) => {
  const { jobId } = req.params;
  try {
    const comments = await query(
      "SELECT * FROM comments WHERE job_id = ? ORDER BY created_at DESC",
      [jobId]
    );
    res.json(comments);
  } catch (error) {
    console.error("Error fetching comments:", error);
    res.status(500).json({ error: "Failed to fetch comments" });
  }
});

// Post new comment
app.post(
  "/api/comments",
  [
    body("user_name").trim().notEmpty().withMessage("Name is required"),
    body("comment_text").trim().notEmpty().withMessage("Comment cannot be empty"),
    body("job_id").isInt().withMessage("Invalid job ID")
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { job_id, user_name, comment_text } = req.body;

    try {
      const insertResult = await query(
        "INSERT INTO comments (job_id, user_name, comment_text) VALUES (?, ?, ?)",
        [job_id, user_name, comment_text]
      );

      const [newComment] = await query("SELECT * FROM comments WHERE id = ?", [insertResult.insertId]);
      res.status(201).json(newComment[0]);
    } catch (error) {
      console.error("Error posting comment:", error);
      res.status(500).json({ error: "Failed to post comment" });
    }
  }
);

// Route to record apply clicks
app.post("/api/jobs/:id/click", async (req, res) => {
  const { id } = req.params;
  const ipAddress = getClientIp(req);

  try {
    await query(
      `INSERT INTO job_clicks (job_id, ip_address, clicked_at)
       VALUES (?, ?, CURRENT_TIMESTAMP)
       ON DUPLICATE KEY UPDATE clicked_at = CURRENT_TIMESTAMP;`,
      [id, ipAddress]
    );

    const [countResult] = await query(
      "SELECT COUNT(DISTINCT ip_address) AS click_count FROM job_clicks WHERE job_id = ?;",
      [id]
    );

    res.status(200).json({
      message: "Click recorded successfully",
      click_count: countResult[0].click_count
    });
  } catch (error) {
    console.error(`Error recording job click: ${error.message}`);
    res.status(500).json({ error: "Failed to record click" });
  }
});

// Get session status
app.get('/api/session/status', authenticateToken, async (req, res) => {
  try {
    const adminId = req.user.id;
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const formattedTodayStart = todayStart.toISOString().slice(0, 19).replace('T', ' ');

    const [activeSession] = await query(
      `SELECT * FROM admin_sessions WHERE admin_id = ? AND end_time IS NULL`,
      [adminId]
    );

    const [todayResult] = await query(
      `SELECT IFNULL(SUM(duration), 0) AS total FROM admin_sessions WHERE admin_id = ? AND start_time >= ?`,
      [adminId, formattedTodayStart]
    );

    res.json({
      isOnline: activeSession.length > 0,
      todayTotal: todayResult[0].total,
      currentSessionStart: activeSession[0]?.start_time || null
    });
  } catch (error) {
    console.error('Error fetching session status:', error);
    res.status(500).json({ error: 'Failed to get session status' });
  }
});

// Get admin statuses
app.get("/api/admins/status/individual", authenticateToken, async (req, res) => {
  try {
    const admins = await query(`
      SELECT a.id,
             CASE WHEN s.admin_id IS NOT NULL THEN 1 ELSE 0 END AS is_online
      FROM admin a
      LEFT JOIN admin_sessions s ON a.id = s.admin_id AND s.end_time IS NULL
      WHERE a.is_approved = TRUE;
    `);
    res.json(admins);
  } catch (error) {
    console.error(`Error fetching admin statuses: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve admin statuses" });
  }
});

// Start session
app.post('/api/session/start', authenticateToken, async (req, res) => {
  try {
    const adminId = req.user.id;
    const [existingSessions] = await query(
      'SELECT * FROM admin_sessions WHERE admin_id = ? AND end_time IS NULL',
      [adminId]
    );

    if (existingSessions.length > 0) {
      return res.status(400).json({ error: 'Session already active' });
    }

    const startTime = new Date();
    await query(
      'INSERT INTO admin_sessions (admin_id, start_time) VALUES (?, ?)',
      [adminId, startTime]
    );

    res.json({ message: 'Session started', startTime });
  } catch (error) {
    console.error('Error starting session:', error);
    res.status(500).json({ error: 'Failed to start session' });
  }
});

// End session
app.post('/api/session/end', authenticateToken, async (req, res) => {
  try {
    const adminId = req.user.id;
    const [activeSessions] = await query(
      'SELECT * FROM admin_sessions WHERE admin_id = ? AND end_time IS NULL',
      [adminId]
    );

    if (activeSessions.length === 0) {
      return res.status(400).json({ error: 'No active session' });
    }

    const endTime = new Date();
    const startTime = activeSessions[0].start_time;
    const duration = Math.floor((endTime - startTime) / 1000); // seconds

    await query(
      `UPDATE admin_sessions 
       SET end_time = ?, duration = ?
       WHERE id = ?`,
      [endTime, duration, activeSessions[0].id]
    );

    res.json({ message: 'Session ended', duration });
  } catch (error) {
    console.error('Error ending session:', error);
    res.status(500).json({ error: 'Failed to end session' });
  }
});

// Update session
app.post('/api/session/update', authenticateToken, async (req, res) => {
  try {
    const adminId = req.user.id;
    const { duration } = req.body;

    if (!Number.isInteger(duration) || duration < 0) {
      return res.status(400).json({ error: "Invalid duration value" });
    }

    await query(
      `UPDATE admin_sessions
       SET duration = ?
       WHERE admin_id = ? AND end_time IS NULL`,
      [duration, adminId]
    );

    res.json({ success: true });
  } catch (error) {
    console.error('Error updating session:', error);
    res.status(500).json({ error: 'Failed to update session' });
  }
});

// Schedule monthly report generation
schedule.scheduleJob('59 23 L * *', async () => {
  try {
    const now = new Date();
    const month = now.getMonth() + 1;
    const year = now.getFullYear();

    await query(
      `INSERT INTO monthly_reports (admin_id, month, year, total_time)
       SELECT 
         admin_id,
         ? as month,
         ? as year,
         SUM(duration) as total
       FROM admin_sessions
       WHERE MONTH(start_time) = ?
         AND YEAR(start_time) = ?
       GROUP BY admin_id`,
      [month, year, month, year]
    );

    console.log('Monthly report generated successfully.');
  } catch (error) {
    console.error('Error generating monthly report:', error);
  }
});

// Create chat room
app.post("/api/chat/rooms", authenticateToken, authorizeAdmin, async (req, res) => {
  const { room_name } = req.body;

  try {
    const [insertResult] = await query(
      "INSERT INTO chat_rooms (room_name) VALUES (?)",
      [room_name]
    );

    const [newRoom] = await query("SELECT * FROM chat_rooms WHERE id = ?", [insertResult.insertId]);
    res.status(201).json(newRoom[0]);
  } catch (error) {
    console.error(`Error creating chat room: ${error.message}`);
    res.status(500).json({ error: "Failed to create chat room" });
  }
});

// Get chat rooms
app.get("/api/chat/rooms", authenticateToken, async (req, res) => {
  try {
    const rooms = await query("SELECT * FROM chat_rooms ORDER BY created_at DESC");
    res.json(rooms);
  } catch (error) {
    console.error(`Error fetching chat rooms: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch chat rooms" });
  }
});

// Send chat message
app.post("/api/chat/messages", authenticateToken, async (req, res) => {
  const { room_id, message } = req.body;
  const sender_id = req.user.id;

  try {
    const [insertResult] = await query(
      "INSERT INTO chat_messages (room_id, sender_id, message) VALUES (?, ?, ?)",
      [room_id, sender_id, message]
    );

    const [newMessage] = await query("SELECT * FROM chat_messages WHERE id = ?", [insertResult.insertId]);
    res.status(201).json(newMessage[0]);
  } catch (error) {
    console.error(`Error sending message: ${error.message}`);
    res.status(500).json({ error: "Failed to send message" });
  }
});

// Get chat messages
app.get("/api/chat/messages/:room_id", authenticateToken, async (req, res) => {
  const { room_id } = req.params;

  try {
    const messages = await query(`
      SELECT cm.*, a.adminname, a.admin_image_link
      FROM chat_messages cm
      JOIN admin a ON cm.sender_id = a.id
      WHERE cm.room_id = ?
      ORDER BY cm.created_at ASC;
    `, [room_id]);
    res.json(messages);
  } catch (error) {
    console.error(`Error fetching messages: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch messages" });
  }
});

// Get direct messages
app.get("/api/chat/direct-messages/:senderPhone/:recipientPhone", authenticateToken, async (req, res) => {
  const { senderPhone, recipientPhone } = req.params;

  try {
    const messages = await query(`
      SELECT dm.*, a.adminname, a.admin_image_link
      FROM direct_messages dm
      JOIN admin a ON dm.sender_phone = a.phone
      WHERE (dm.sender_phone = ? AND dm.recipient_phone = ?)
         OR (dm.sender_phone = ? AND dm.recipient_phone = ?)
      ORDER BY dm.created_at ASC;
    `, [senderPhone, recipientPhone, recipientPhone, senderPhone]);
    res.json(messages);
  } catch (error) {
    console.error("Error fetching direct messages:", error.message);
    res.status(500).json({ error: "Failed to fetch direct messages" });
  }
});

// Send direct message
app.post("/api/chat/direct-messages", authenticateToken, async (req, res) => {
  const { recipient_phone, message } = req.body;
  const sender_phone = req.user.phone;

  if (!recipient_phone?.match(/^(\+\d{1,3})?\d{10}$/)) {
    return res.status(400).json({ error: "Invalid recipient phone format" });
  }

  if (!message?.trim() || message.length > 500) {
    return res.status(400).json({
      error: "Message must be between 1-500 characters"
    });
  }

  try {
    const [recipientCheck] = await query("SELECT * FROM admin WHERE phone = ?", [recipient_phone]);
    if (recipientCheck.length === 0) {
      return res.status(404).json({ error: "Recipient not found" });
    }

    const [insertResult] = await query(
      `INSERT INTO direct_messages (sender_phone, recipient_phone, message)
       VALUES (?, ?, ?)`,
      [sender_phone, recipient_phone, message]
    );

    const [senderResult] = await query(
      "SELECT adminname, admin_image_link FROM admin WHERE phone = ?",
      [sender_phone]
    );

    const messageWithDetails = {
      id: insertResult.insertId,
      sender_phone,
      recipient_phone,
      message,
      created_at: new Date(),
      adminname: senderResult[0].adminname,
      admin_image_link: senderResult[0].admin_image_link
    };

    // Broadcast over WebSocket
    wss.clients.forEach(client => {
      if (
        client.readyState === WebSocket.OPEN &&
        (client.userPhone === sender_phone || client.userPhone === recipient_phone)
      ) {
        client.send(JSON.stringify({
          type: 'direct_message',
          message: messageWithDetails
        }));
      }
    });

    res.status(201).json(messageWithDetails);
  } catch (error) {
    console.error("Error sending direct message:", error.message);
    res.status(500).json({
      error: "Failed to send direct message",
      details: error.message
    });
  }
});

// Get approved admins
app.get("/api/admins/approved", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const admins = await query(`
      SELECT 
        id, 
        adminname, 
        username, 
        phone, 
        admin_image_link, 
        createdAt
      FROM admin 
      WHERE is_approved = TRUE
      ORDER BY createdAt DESC;
    `);
    res.json(admins);
  } catch (error) {
    console.error(`Error fetching admins: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve admins" });
  }
});

// Get all admins
app.get("/api/admins", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const admins = await query(`
      SELECT 
        id, 
        adminname, 
        username, 
        phone, 
        admin_image_link, 
        createdAt
      FROM admin 
      ORDER BY createdAt DESC;
    `);
    res.json(admins);
  } catch (error) {
    console.error(`Error fetching admins: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve admins" });
  }
});

// Get current admin
app.get("/api/admin/me", authenticateToken, async (req, res) => {
  try {
    const { id } = req.user;
    const [adminResult] = await query("SELECT * FROM admin WHERE id = ?", [id]);

    if (adminResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const admin = adminResult[0];
    res.json({
      adminname: admin.adminname,
      username: admin.username,
      phone: admin.phone,
      admin_image_link: admin.admin_image_link,
      createdAt: admin.createdAt,
    });
  } catch (error) {
    console.error(`Error fetching admin details: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve admin details" });
  }
});

// Update admin details
app.put(
  "/api/admin/update",
  authenticateToken,
  [
    body("adminname").optional().isString(),
    body("username").optional().isString(),
    body("phone").optional().isString(),
    body("admin_image_link").optional().isURL(),
    body("password").optional().isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ errors: errors.array() });

    const { adminname, username, phone, admin_image_link, password } = req.body;
    const adminId = req.user.id;

    try {
      if (username || phone) {
        const [existingAdmins] = await query(
          "SELECT * FROM admin WHERE (username = ? OR phone = ?) AND id != ?",
          [username, phone, adminId]
        );

        if (existingAdmins.length > 0) {
          return res
            .status(400)
            .json({ error: "Username or phone already in use by another admin" });
        }
      }

      const updates = [];
      const values = [];

      if (adminname) {
        updates.push("adminname = ?");
        values.push(adminname);
      }
      if (username) {
        updates.push("username = ?");
        values.push(username);
      }
      if (phone) {
        updates.push("phone = ?");
        values.push(phone);
      }
      if (admin_image_link) {
        updates.push("admin_image_link = ?");
        values.push(admin_image_link);
      }
      if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        updates.push("password = ?");
        values.push(hashedPassword);
      }

      if (updates.length === 0) {
        return res.status(400).json({ error: "No fields to update" });
      }

      values.push(adminId);

      const updateQuery = `UPDATE admin SET ${updates.join(", ")} WHERE id = ?`;
      await query(updateQuery, values);

      res.json({ message: "Admin details updated successfully" });
    } catch (error) {
      console.error(`Error updating admin details: ${error.message}`);
      res.status(500).json({ error: "Failed to update admin details" });
    }
  }
);

// Reset password
app.post("/api/admin/forgot-password", async (req, res) => {
  const { username, newPassword } = req.body;

  if (!username || !newPassword) {
    return res.status(400).json({ error: "Username and new password are required" });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters long" });
  }

  try {
    const [adminResult] = await query(
      "SELECT id FROM admin WHERE username = ?",
      [username]
    );

    if (adminResult.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const adminId = adminResult[0].id;
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await query(
      "UPDATE admin SET password = ? WHERE id = ?",
      [hashedPassword, adminId]
    );

    res.json({ message: "Password reset successfully" });
  } catch (error) {
    console.error(`Error resetting password: ${error.message}`);
    res.status(500).json({ error: "Failed to reset password" });
  }
});

const isFirstAdmin = async (adminId) => {
  try {
    const result = await pool.query(
      "SELECT created_by, is_approved FROM admin WHERE id = $1",
      [adminId]
    );
    return result.rows[0].created_by === null && result.rows[0].is_approved;
  } catch (error) {
    console.error("Error checking if admin is first admin:", error);
    return false;
  }
};

// Get all jobs with pagination
app.get("/api/jobs", async (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = parseInt(req.query.limit) || 8;
  const offset = (page - 1) * limit;

  try {
    const currentTime = new Date();
    const sevenDaysAgo = new Date(currentTime);
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    const jobs = await query(
      `SELECT *,
      CASE
        WHEN createdAt >= ? THEN 1
        ELSE 0
      END AS isNew
      FROM job
      ORDER BY isNew DESC, createdAt DESC
      LIMIT ? OFFSET ?;`,
      [
        sevenDaysAgo.toISOString().slice(0, 19).replace('T', ' '),
        limit,
        offset,
      ]
    );

    if (jobs.length === 0) {
      return res.status(404).json({ error: "No jobs found" });
    }

    res.json(jobs);
  } catch (error) {
    console.error(`Error fetching all jobs: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve jobs" });
  }
});

// Admin panel - get all jobs
app.get("/api/jobs/adminpanel", authenticateToken, authorizeAdmin, async (req, res) => {
  const viewAll = req.query.view === "all";
  const adminId = req.user.id;

  try {
    let sql = `
      SELECT j.*,
        creator.admin_image_link AS creator_admin_image,
        creator.adminname AS creator_name,
        approver.adminname AS approver_name
      FROM job j
      LEFT JOIN admin creator ON j.created_by = creator.id
      LEFT JOIN admin approver ON j.approved_by = approver.id
    `;

    const params = [];
    if (!viewAll) {
      sql += " WHERE j.created_by = ?";
      params.push(adminId);
    }

    const result = await query(sql, params);
    res.json(result);
  } catch (error) {
    console.error("Error retrieving jobs:", error);
    res.status(500).send("An error occurred while retrieving jobs.");
  }
});

// Delete job and related data
app.delete("/api/jobs/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    await query("DELETE FROM job_approval_requests WHERE job_id = ?", [id]);
    await query("DELETE FROM job_viewers WHERE job_id = ?", [id]);
    await query("DELETE FROM job_clicks WHERE job_id = ?", [id]);
    await query("DELETE FROM comments WHERE job_id = ?", [id]);
    await query("DELETE FROM resumes WHERE job_id = ?", [id]);

    const [deleteResult] = await query("DELETE FROM job WHERE id = ?", [id]);

    if (deleteResult.affectedRows === 0) {
      return res.status(404).json({ error: "Job not found" });
    }

    res.json({ message: "Job deleted successfully" });
  } catch (error) {
    console.error(`Error deleting job: ${error.message}`);
    res.status(500).json({ error: "Failed to delete job" });
  }
});

// Add new job
app.post(
  "/api/jobs",
  authenticateToken,
  authorizeAdmin,
  [
    body("companyname").notEmpty().withMessage("Company name is required"),
    body("title").notEmpty().withMessage("Job title is required"),
    body("description").notEmpty().withMessage("Description is required"),
    body("apply_link").isURL().withMessage("Apply link must be a valid URL"),
    body("image_link").isURL().withMessage("Image link must be a valid URL"),
    body("url").notEmpty().withMessage("Job URL is required"),
    body("salary").notEmpty().withMessage("Salary is required"),
    body("location").notEmpty().withMessage("Location is required"),
    body("job_type").notEmpty().withMessage("Job type is required"),
    body("experience").notEmpty().withMessage("Experience is required"),
    body("batch").notEmpty().withMessage("Batch is required"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const {
      companyname,
      title,
      description,
      apply_link,
      image_link,
      url,
      salary,
      location,
      job_type,
      experience,
      batch,
      advanced_data,
    } = req.body;
    const adminId = req.user.id;

    try {
      const [adminResult] = await query("SELECT adminname FROM admin WHERE id = ?", [adminId]);
      if (adminResult.length === 0) {
        return res.status(404).json({ error: "Admin not found" });
      }
      const adminName = adminResult[0].adminname;

      const [insertResult] = await query(
        `INSERT INTO job 
          (companyname, title, description, apply_link, image_link, url, salary, location, job_type, experience, batch, job_uploader, created_by, advanced_data)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`,
        [
          companyname,
          title,
          description,
          apply_link,
          image_link,
          url,
          salary,
          location,
          job_type,
          experience,
          batch,
          adminName,
          adminId,
          advanced_data || null,
        ]
      );

      res.status(201).json({ message: "Job added successfully", jobId: insertResult.insertId });
    } catch (error) {
      console.error(`Error adding job: ${error.message}`);
      res.status(500).json({ error: "Failed to add job" });
    }
  }
);

// Approve job
app.put("/api/jobs/:id/approve", authenticateToken, authorizeAdmin, async (req, res) => {
  const jobId = req.params.id;
  const approverId = req.user.id;

  try {
    const [updateResult] = await query(
      `UPDATE job SET status = 'approved', approved_by = ? WHERE id = ?`,
      [approverId, jobId]
    );

    if (updateResult.affectedRows === 0) {
      return res.status(404).json({ error: "Job not found" });
    }

    res.json({ message: "Job approved successfully" });
  } catch (error) {
    console.error(`Error approving job: ${error.message}`);
    res.status(500).json({ error: "Failed to approve job" });
  }
});

// Update job
app.put("/api/jobs/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const {
    companyname,
    title,
    description,
    apply_link,
    image_link,
    url,
    salary,
    location,
    job_type,
    experience,
    batch,
    advanced_data,
  } = req.body;

  try {
    const [existingJob] = await query("SELECT * FROM job WHERE id = ?;", [id]);
    if (existingJob.length === 0) {
      return res.status(404).json({ error: "Job not found" });
    }

    const job = existingJob.rows[0]
    const adminIsFirst = await isFirstAdmin(req.user.id)

    if (!adminIsFirst && job.created_by !== req.user.id) {
      return res.status(403).json({ error: "Not authorized" })
    }
    const [adminResult] = await query("SELECT * FROM admin WHERE id = ?;", [req.user.id]);
    const admin = adminResult[0];
    if (!admin) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const jobUploader = admin.adminname;

    const [updateResult] = await query(
      `UPDATE job
      SET companyname = ?, title = ?, description = ?, apply_link = ?, image_link = ?, url = ?, salary = ?, location = ?, job_type = ?, experience = ?, batch = ?, job_uploader = ?, advanced_data = ?
      WHERE id = ?;`,
      [
        companyname,
        title,
        description,
        apply_link,
        image_link,
        url,
        salary,
        location,
        job_type,
        experience,
        batch,
        jobUploader,
        advanced_data || null,
        id,
      ]
    );

    if (updateResult.affectedRows === 0) {
      return res.status(500).json({ error: "Failed to update job" });
    }

    res.json({ message: "Job updated successfully" });
  } catch (error) {
    console.error(`Error updating job: ${error.message}`);
    res.status(500).json({ error: "Failed to update job" });
  }
});

// Get job by company name and URL
app.get('/api/jobs/company/:companyname/:url', async (req, res) => {
  const { companyname, url } = req.params;

  try {
    const jobs = await query(
      `SELECT j.*, 
        (SELECT COUNT(DISTINCT ip_address) FROM job_clicks WHERE job_id = j.id) AS click_count
      FROM job j
      WHERE 
        regexp_replace(LOWER(j.companyname), '[^a-z0-9]', '', 'g') = regexp_replace(LOWER(?), '[^a-z0-9]', '', 'g')
        AND LOWER(j.url) = LOWER(?);`,
      [companyname, url]
    );

    if (jobs.length) {
      res.json(jobs[0]);
    } else {
      res.status(404).json({ error: "Job not found" });
    }
  } catch (error) {
    console.error(`Error fetching job by company name and URL: ${error.message}`);
    res.status(500).json({ error: "Failed to fetch job" });
  }
});

// Record job view
app.post("/api/jobs/:id/view", async (req, res) => {
  const { id } = req.params;
  const ipAddress = getClientIp(req);

  try {
    await query(
      `INSERT INTO job_viewers (job_id, ip_address, viewed_at)
      VALUES (?, ?, CURRENT_TIMESTAMP)
      ON DUPLICATE KEY UPDATE viewed_at = CURRENT_TIMESTAMP;`,
      [id, ipAddress]
    );
    res.status(200).json({ message: "View recorded successfully" });
  } catch (error) {
    console.error(`Error recording job view: ${error.message}`);
    res.status(500).json({ error: "Failed to record view" });
  }
});

// Get job viewers count
app.get("/api/jobs/:id/viewers", async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await query(
      `SELECT COUNT(DISTINCT ip_address) AS viewer_count
      FROM job_viewers
      WHERE job_id = ?;`,
      [id]
    );
    res.json({ viewer_count: result[0].viewer_count });
  } catch (error) {
    console.error(`Error fetching viewers count: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve viewer count" });
  }
});

// Get latest popup
app.get("/api/popup", async (req, res) => {
  try {
    const [popupResult] = await query(
      "SELECT * FROM popup_content ORDER BY created_at DESC LIMIT 1;"
    );
    res.json({ popup: popupResult[0] || null });
  } catch (error) {
    console.error(`Error fetching popup content: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve popup content" });
  }
});

// Admin Panel: Get all popups
app.get("/api/popup/adminpanel", authenticateToken, authorizeAdmin, async (req, res) => {
  try {
    const popups = await query("SELECT * FROM popup_content ORDER BY created_at DESC;");
    res.json(popups);
  } catch (error) {
    console.error(`Error fetching all popup content: ${error.message}`);
    res.status(500).json({ error: "Failed to retrieve popup content" });
  }
});

// Admin Panel: Add new popup
app.post("/api/popup/adminpanel", authenticateToken, authorizeAdmin, [
  body("popup_heading").notEmpty().withMessage("Popup heading is required"),
  body("popup_text").notEmpty().withMessage("Popup text is required"),
  body("popup_link").isURL().withMessage("Popup link must be a valid URL"),
  body("popup_routing_link").isURL().withMessage("Popup routing link must be a valid URL"),
  body("popup_belowtext").notEmpty().withMessage("Popup belowtext is required"),
],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const { popup_heading, popup_text, popup_link, popup_routing_link, popup_belowtext } = req.body;

    try {
      const [insertResult] = await query(
        `INSERT INTO popup_content (popup_heading, popup_text, popup_link, popup_belowtext, popup_routing_link)
        VALUES (?, ?, ?, ?, ?);`,
        [popup_heading, popup_text, popup_link, popup_belowtext, popup_routing_link]
      );
      res.status(201).json({ message: "Popup added successfully", id: insertResult.insertId });
    } catch (error) {
      console.error(`Error adding popup: ${error.message}`);
      res.status(500).json({ error: "Failed to add popup" });
    }
  }
);

// Admin Panel: Update popup
app.put("/api/popup/adminpanel/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const { popup_heading, popup_text, popup_link, popup_routing_link, popup_belowtext } = req.body;

  try {
    const [existingPopup] = await query("SELECT * FROM popup_content WHERE id = ?;", [id]);
    if (existingPopup.length === 0) {
      return res.status(404).json({ error: "Popup not found" });
    }

    await query(
      `UPDATE popup_content
      SET popup_heading = ?, popup_text = ?, popup_link = ?, popup_routing_link = ?, popup_belowtext = ?
      WHERE id = ?;`,
      [popup_heading, popup_text, popup_link, popup_routing_link, popup_belowtext, id]
    );
    res.json({ message: "Popup content updated successfully" });
  } catch (error) {
    console.error(`Error updating popup content: ${error.message}`);
    res.status(500).json({ error: "Failed to update popup content" });
  }
});

// Admin Panel: Delete popup
app.delete("/api/popup/adminpanel/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const [existingPopup] = await query("SELECT * FROM popup_content WHERE id = ?;", [id]);
    if (existingPopup.length === 0) {
      return res.status(404).json({ error: "Popup not found" });
    }

    await query("DELETE FROM popup_content WHERE id = ?;", [id]);
    res.json({ message: "Popup content deleted successfully" });
  } catch (error) {
    console.error(`Error deleting popup content: ${error.message}`);
    res.status(500).json({ error: "Failed to delete popup content" });
  }
});
// Enhanced resume analysis function
function analyzeResume(resumeText, jobDescription) {
  // Extract job requirements
  const requirements = extractRequirements(jobDescription)

  // Extract skills from resume
  const skills = extractSkills(resumeText)

  // Compare requirements and skills
  const { pros, cons, summary } = compareRequirementsAndSkills(requirements, skills, resumeText)

  // Calculate match percentage based on matched requirements
  const matchedRequirements = requirements.filter((req) =>
    skills.some((skill) => req.toLowerCase().includes(skill.toLowerCase())),
  )

  const matchPercentage = requirements.length > 0 ? (matchedRequirements.length / requirements.length) * 100 : 50 // Default to 50% if no requirements found

  return {
    matchPercentage,
    skills,
    experience: extractExperience(resumeText),
    pros,
    cons,
    summary,
  }
}
// Resume analysis functions
function extractRequirements(description) {
  if (!description) return [];
  const lines = description
    .split(/[\n•\-*]/)
    .map(line => line.trim())
    .filter(line => line.length > 0);
  const requirementKeywords = ["experience", "knowledge", "skill", "proficiency", "ability", "familiar", "understand"];
  const requirements = lines.filter(line =>
    requirementKeywords.some(keyword => line.toLowerCase().includes(keyword)) ||
    line.toLowerCase().includes("years") ||
    /^[A-Z]/.test(line)
  );
  return requirements.length > 0 ? requirements : lines.slice(0, 5);
}

function extractSkills(text) {
  const technicalSkills = [
    "JavaScript", "React", "Angular", "Vue", "Node.js", "Express", "Python", "Java", "C#", "C++", "PHP", "Ruby",
    "Swift", "Kotlin", "Go", "Rust", "SQL", "NoSQL", "MongoDB", "PostgreSQL", "MySQL", "Oracle", "Firebase",
    "AWS", "Azure", "GCP", "Docker", "Kubernetes", "Git", "HTML", "CSS", "SASS", "LESS", "Bootstrap", "Tailwind",
    "TypeScript", "Redux", "GraphQL", "REST API", "SOAP", "CI/CD", "Jenkins", "Travis", "Agile", "Scrum", "Kanban",
    "Jira", "TDD", "BDD", "Unit Testing", "Integration Testing", "E2E Testing", "Jest", "Mocha", "Chai", "Selenium",
    "Cypress", "Webpack", "Babel", "ESLint", "Prettier", "Linux", "Windows", "MacOS", "Mobile Development", "iOS",
    "Android", "React Native", "Flutter", "Xamarin", "UI/UX", "Figma", "Sketch", "Adobe XD", "Photoshop", "Illustrator",
    "InDesign", "After Effects", "Data Analysis", "Machine Learning", "AI", "Deep Learning", "NLP", "Computer Vision",
    "TensorFlow", "PyTorch", "Keras", "scikit-learn", "pandas", "numpy", "R", "Tableau", "Power BI", "Excel", "VBA",
    "SharePoint", "Salesforce", "SAP", "ERP", "CRM"
  ];

  const softSkills = [
    "Communication", "Teamwork", "Problem Solving", "Critical Thinking", "Creativity", "Leadership",
    "Time Management", "Adaptability", "Flexibility", "Work Ethic", "Attention to Detail",
    "Organization", "Interpersonal Skills", "Conflict Resolution", "Decision Making", "Stress Management",
    "Emotional Intelligence", "Collaboration", "Negotiation", "Persuasion", "Presentation", "Public Speaking",
    "Customer Service", "Project Management", "Multitasking", "Self-Motivation", "Initiative", "Persistence"
  ];

  const allSkills = [...technicalSkills, ...softSkills];
  const foundSkills = allSkills.filter(skill => new RegExp(`\\b${skill}\\b`, "i").test(text));

  return foundSkills.map(skill => {
    const expMatch = text.match(new RegExp(`(\\d+)\\s*(?:years?|yrs?)\\s*(?:of)?\\s*(?:experience)?\\s*(?:with|in)\\s*${skill}`, "i"));
    return expMatch ? `${skill} (${expMatch[1]} years)` : skill;
  });
}

function extractExperience(text) {
  const expMatch = text.match(/(\d+)\+?\s*years?(?:\s*of)?\s*experience/i);
  if (expMatch) return expMatch[0];

  const jobTitleMatch = text.match(
    /(?:senior|junior|lead|principal|staff)?\s*(?:software|web|frontend|backend|fullstack|mobile)?\s*(?:engineer|developer|architect|designer)/i
  );
  return jobTitleMatch ? `${jobTitleMatch[0]} experience` : "Experience level not specified";
}

function compareRequirementsAndSkills(requirements, skills, resumeText) {
  const pros = [];
  const cons = [];
  const lowerCaseSkills = skills.map(skill => skill.toLowerCase());
  const lowerCaseResumeText = resumeText.toLowerCase();

  requirements.forEach(req => {
    const lowerReq = req.toLowerCase();
    const hasMatch = lowerCaseSkills.some(skill => lowerReq.includes(skill.replace(/\s*\(\d+\s*years\)/, ""))) ||
      lowerCaseResumeText.includes(lowerReq);
    hasMatch ? pros.push(`Candidate has experience with ${req}`) : cons.push(`Candidate lacks experience with ${req}`);
  });

  skills.forEach(skill => {
    const cleanSkill = skill.replace(/\s*\(\d+\s*years\)/, "");
    const isExtraSkill = !requirements.some(req => req.toLowerCase().includes(cleanSkill.toLowerCase()));
    if (isExtraSkill) pros.push(`Candidate has additional skill: ${skill}`);
  });

  const matchPercentage = requirements.length > 0 ?
    (pros.length / requirements.length) * 100 : 50;

  let summary = "";
  if (pros.length > cons.length) {
    summary = `The candidate matches ${pros.length} out of ${requirements.length} job requirements. The candidate has the relevant skills for this position but may need training in some specific areas.`;
  } else if (pros.length < cons.length) {
    summary = `The candidate matches ${pros.length} out of ${requirements.length} job requirements. While the candidate has some relevant skills, there are significant gaps in meeting the job requirements.`;
  } else {
    summary = `The candidate matches ${pros.length} out of ${requirements.length} job requirements. The candidate has a balanced profile with both strengths and areas for improvement relative to this position.`;
  }

  return {
    matchPercentage,
    pros: pros.slice(0, 5),
    cons: cons.slice(0, 5),
    summary
  };
}
// Edit group chat room (Admin only)
app.put("/api/chat/rooms/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;
  const { room_name } = req.body;

  try {
    // Check for existing room with same name (excluding current room)
    const [existingRoom] = await query(
      "SELECT * FROM chat_rooms WHERE room_name = ? AND id != ?",
      [room_name, id]
    );

    if (existingRoom.length > 0) {
      return res.status(400).json({ error: "Room name already exists" });
    }

    // Update room name
    await query(
      "UPDATE chat_rooms SET room_name = ? WHERE id = ?",
      [room_name, id]
    );

    // Fetch updated room
    const [updatedRoom] = await query(
      "SELECT * FROM chat_rooms WHERE id = ?",
      [id]
    );

    if (!updatedRoom.length) {
      return res.status(404).json({ error: "Room not found" });
    }

    res.json(updatedRoom[0]);
  } catch (error) {
    console.error(`Error updating room: ${error.message}`);
    res.status(500).json({ error: "Failed to update room" });
  }
});

// Delete group chat room (Admin only)
app.delete("/api/chat/rooms/:id", authenticateToken, authorizeAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    // Delete related messages first
    await query("DELETE FROM chat_messages WHERE room_id = ?", [id]);

    const [deleteResult] = await query("DELETE FROM chat_rooms WHERE id = ?", [id]);

    if (deleteResult.affectedRows === 0) {
      return res.status(404).json({ error: "Room not found" });
    }

    res.json({ message: "Room deleted successfully" });
  } catch (error) {
    console.error(`Error deleting room: ${error.message}`);
    res.status(500).json({ error: "Failed to delete room" });
  }
});

// Edit group message
app.put("/api/chat/messages/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { message } = req.body;
    const userId = req.user.id;

    const [updateResult] = await query(
      `UPDATE chat_messages 
       SET message = ? 
       WHERE id = ? AND sender_id = ?`,
      [message, id, userId]
    );

    if (updateResult.affectedRows === 0) {
      return res.status(403).json({ error: "Not authorized or message not found" });
    }

    // Fetch updated message
    const [updatedMessages] = await query("SELECT * FROM chat_messages WHERE id = ?", [id]);
    res.json(updatedMessages[0]);
  } catch (error) {
    console.error("Error updating message:", error);
    res.status(500).json({ error: "Failed to update message" });
  }
});

// Delete group message
app.delete("/api/chat/messages/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const userId = req.user.id;

    const [deleteResult] = await query(
      `DELETE FROM chat_messages 
       WHERE id = ? AND sender_id = ?`,
      [id, userId]
    );

    if (deleteResult.affectedRows === 0) {
      return res.status(403).json({ error: "Not authorized or message not found" });
    }

    res.json({ message: "Message deleted successfully" });
  } catch (error) {
    console.error("Error deleting message:", error);
    res.status(500).json({ error: "Failed to delete message" });
  }
});

// Edit direct message
app.put("/api/chat/direct-messages/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { message } = req.body;
    const senderPhone = req.user.phone;

    const [updateResult] = await query(
      `UPDATE direct_messages 
       SET message = ? 
       WHERE id = ? AND sender_phone = ?`,
      [message, id, senderPhone]
    );

    if (updateResult.affectedRows === 0) {
      return res.status(403).json({ error: "Not authorized or message not found" });
    }

    // Fetch updated message
    const [updatedMessages] = await query(
      "SELECT * FROM direct_messages WHERE id = ?",
      [id]
    );
    res.json(updatedMessages[0]);
  } catch (error) {
    console.error("Error updating direct message:", error);
    res.status(500).json({ error: "Failed to update message" });
  }
});

// Delete direct message
app.delete("/api/chat/direct-messages/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const senderPhone = req.user.phone;

    const [deleteResult] = await query(
      `DELETE FROM direct_messages 
       WHERE id = ? AND sender_phone = ?`,
      [id, senderPhone]
    );

    if (deleteResult.affectedRows === 0) {
      return res.status(403).json({ error: "Not authorized or message not found" });
    }

    res.json({ message: "Message deleted successfully" });
  } catch (error) {
    console.error("Error deleting direct message:", error);
    res.status(500).json({ error: "Failed to delete message" });
  }
});



// Get all analyzed resumes (general analysis)
app.get('/api/analyzed-resumes', async (req, res) => {
  try {
    const resumes = await query(`
      SELECT id, name, email, phone, skills, experience, 
             match_percentage, uploaded_at
      FROM resumes
      WHERE job_id IS NULL
      ORDER BY uploaded_at DESC
    `);
    res.json(resumes);
  } catch (error) {
    console.error('Error fetching analyzed resumes:', error);
    res.status(500).json({ error: 'Failed to fetch resumes' });
  }
});

// Download analyzed resume
app.get('/api/analyzed-resumes/:id/download', async (req, res) => {
  try {
    const resumes = await query(
      'SELECT * FROM resumes WHERE id = ? AND job_id IS NULL',
      [req.params.id]
    );

    if (resumes.length === 0) return res.status(404).send('Resume not found');

    const resume = resumes[0];
    res.set({
      'Content-Type': resume.file_type,
      'Content-Disposition': `attachment; filename="${resume.name}_resume.${resume.file_type.split('/')[1]}"`
    });
    res.send(resume.resume_file);
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).send('Download failed');
  }
});
// Update resume status
app.put('/api/jobs/:jobId/resumes/:resumeId/status', async (req, res) => {
  const { jobId, resumeId } = req.params;
  const { status } = req.body;
  const valid = ['pending', 'reviewed', 'shortlisted', 'rejected', 'hired'];

  if (!status || !valid.includes(status)) {
    return res.status(400).json({
      error: "Valid status required",
      valid_statuses: valid
    });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // Check job exists
    const jobCheck = await client.query('SELECT id FROM job WHERE id = $1', [jobId]);
    if (!jobCheck.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: "Job not found" });
    }

    // Check resume exists
    const resumeCheck = await client.query('SELECT id FROM resumes WHERE id = $1 AND job_id = $2', [resumeId, jobId]);
    if (!resumeCheck.rows.length) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: "Resume not found for this job" });
    }

    // Update status
    await client.query(
      'UPDATE resumes SET status = $1 WHERE id = $2',
      [status, resumeId]
    );

    await client.query('COMMIT');
    res.json({
      success: true,
      message: 'Resume status updated',
      jobId,
      resumeId,
      status
    });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error updating resume status:', err);
    res.status(500).json({ error: 'Failed to update resume status' });
  } finally {
    client.release();
  }
});

// Enhanced Resume Analysis Function for Multiple Jobs
const analyzeResumeForAllJobs = (resumeText, jobs) => {
  // Extract skills and experience from resume once
  const skills = extractSkills(resumeText);
  const experience = extractExperience(resumeText);

  // Analyze against each job
  const jobAnalyses = jobs.map(job => {
    const requirements = extractRequirements(job.description);
    const matchedRequirements = requirements.filter(req =>
      skills.some(skill => req.toLowerCase().includes(skill.toLowerCase()))
    );

    const matchPercentage = requirements.length > 0
      ? (matchedRequirements.length / requirements.length) * 100
      : 50;

    return {
      jobId: job.id,
      title: job.title,
      company: job.companyname,
      matchPercentage,
      requirements: {
        total: requirements.length,
        matched: matchedRequirements.length
      }
    };
  });

  // Calculate overall statistics
  const totalMatch = jobAnalyses.reduce((sum, analysis) => sum + analysis.matchPercentage, 0);
  const averageMatch = totalMatch / jobAnalyses.length;

  // Get top 3 matches
  const topMatches = [...jobAnalyses]
    .sort((a, b) => b.matchPercentage - a.matchPercentage)
    .slice(0, 3);

  return {
    averageMatch,
    topMatches,
    skills,
    experience,
    totalJobsAnalyzed: jobs.length
  };
};
// Upload resume for specific job
app.post("/api/jobs/:id/upload-resume", upload.single('resume'), async (req, res) => {
  try {
    const jobId = req.params.id;
    const { name, email, phone } = req.body;
    const file = req.file;

    if (!file) return res.status(400).json({ error: "No file uploaded" });

    let text = "";
    if (file.mimetype === "application/pdf") {
      const pdfData = await pdfParse(file.buffer);
      text = pdfData.text;
    } else {
      const result = await mammoth.extractRawText({ buffer: file.buffer });
      text = result.value;
    }

    const [job] = await query("SELECT * FROM job WHERE id = ?", [jobId]);
    if (job.length === 0) return res.status(404).json({ error: "Job not found" });

    const requirements = extractRequirements(job[0].description);
    const skills = extractSkills(text);
    const { matchPercentage, pros, cons, summary } = compareRequirementsAndSkills(requirements, skills, text);

    await query(
      `INSERT INTO resumes (job_id, name, email, phone, resume_file, file_type, skills, experience, match_percentage)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        jobId,
        name,
        email,
        phone,
        file.buffer,
        file.mimetype,
        JSON.stringify(skills),
        extractExperience(text),
        matchPercentage,
      ]
    );

    res.json({
      matchPercentage,
      skills,
      experience: extractExperience(text),
      pros,
      cons,
      summary,
      resumeFileName: file.originalname
    });
  } catch (error) {
    console.error("Resume upload error:", error);
    res.status(500).json({ error: "Resume processing failed" });
  }
});

// Analyze resume for all jobs
app.post('/api/analyze-resume', upload.single('resume'), async (req, res) => {
  try {
    const file = req.file;
    const { name, email, phone } = req.body;

    if (!file) return res.status(400).json({ error: 'No file uploaded' });
    if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });

    let text = '';
    if (file.mimetype === 'application/pdf') {
      const pdfData = await pdfParse(file.buffer);
      text = pdfData.text;
    } else {
      const result = await mammoth.extractRawText({ buffer: file.buffer });
      text = result.value;
    }

    const jobs = await query('SELECT id, companyname, title, description FROM job');
    const skills = extractSkills(text);
    const experience = extractExperience(text);
    const analysisResult = analyzeResumeForAllJobs(text, jobs);

    const jobAnalyses = jobs.map(job => {
      const requirements = extractRequirements(job.description);
      const { matchPercentage } = compareRequirementsAndSkills(requirements, skills, text);
      return {
        jobId: job.id,
        title: job.title,
        company: job.companyname,
        matchPercentage,
        requirements: {
          total: requirements.length,
          matched: Math.floor((matchPercentage / 100) * requirements.length)
        },
      };
    });

    const totalMatch = jobAnalyses.reduce((sum, analysis) => sum + analysis.matchPercentage, 0);
    const averageMatch = totalMatch / jobAnalyses.length;
    const topMatches = [...jobAnalyses].sort((a, b) => b.matchPercentage - a.matchPercentage).slice(0, 3);

    await query(
      `INSERT INTO resumes (name, email, phone, resume_file, file_type, skills, experience, match_percentage)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        name,
        email,
        phone || null,
        file.buffer,
        file.mimetype,
        JSON.stringify(skills),
        experience,
        averageMatch,
        analysisResult.skills,
        analysisResult.experience,
        analysisResult.averageMatch
      ]
    );

    res.json({
      success: true,
      score: averageMatch,
      skills,
      experience,
      topMatches,
      totalJobsAnalyzed: jobs.length,
    });
  } catch (error) {
    console.error('Resume analysis error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to analyze resume',
      details: error.message,
    });
  }
});

// Get resumes
app.get('/api/public/resumes', async (req, res) => {
  try {
    const resumes = await query(`
      SELECT r.*, 
             j.title AS job_title,
             j.companyname AS job_companyname,
             j.url AS job_url
      FROM resumes r
      LEFT JOIN job j ON r.job_id = j.id
      ORDER BY uploaded_at DESC
    `);
    res.json(resumes);
  } catch (error) {
    console.error('Error fetching resumes:', error);
    res.status(500).json({ error: 'Failed to fetch resumes' });
  }
});

// Download resume
app.get('/api/resumes/:id/download', async (req, res) => {
  try {
    const resumes = await query('SELECT * FROM resumes WHERE id = ?', [req.params.id]);
    if (resumes.length === 0) return res.status(404).send('Resume not found');

    const resume = resumes[0];
    res.set({
      'Content-Type': resume.file_type,
      'Content-Disposition': `attachment; filename="${resume.name}_resume.${resume.file_type.split('/')[1]}"`
    });
    res.send(resume.resume_file);
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).send('Download failed');
  }
});

// Career chatbot
app.post('/api/chatbot', async (req, res) => {
  try {
    const { message } = req.body;
    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return res.status(400).json({ error: 'Invalid message content' });
    }

    const completion = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [
        {
          role: 'system',
          content: `You are CareerGPT, an AI career assistant specializing in job search strategies, resume optimization, interview preparation, career development, salary negotiation, and tech industry insights. Provide concise, actionable advice.`,
        },
        {
          role: 'user',
          content: message.trim(),
        },
      ],
      max_tokens: 500,
      temperature: 0.7,
    });

    const responseText = completion.choices[0].message.content;
    await query('INSERT INTO chat_history (query, response) VALUES (?, ?)', [message, responseText]);

    res.json({ success: true, reply: responseText });
  } catch (error) {
    console.error('Chat error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to process message',
      system: 'Our career assistant is currently unavailable. Please try again later.',
    });
  }
});

// Google OAuth start
app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google OAuth callback
app.get('/api/auth/google/callback', passport.authenticate('google', { session: false }), (req, res) => {
  const token = jwt.sign(
    {
      id: req.user.id,
      googleId: req.user.google_id,
      displayName: req.user.display_name,
      email: req.user.email,
      photoURL: req.user.photo_url,
    },
    JWT_SECRET,
    { expiresIn: '7d' }
  );

  const nonce = res.locals.nonce || '';

  res.send(`
    <html>
      <body>
        <script nonce="${nonce}">
          window.opener.postMessage({ token: "${token}" }, "${process.env.FRONTEND_URL || '*'}");
          window.close();
        </script>
      </body>
    </html>
  `);
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const [user] = await query(
      'SELECT id, google_id, display_name, email, photo_url FROM users WHERE id = ?',
      [req.user.id]
    );

    if (user.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      id: user[0].id,
      googleId: user[0].google_id,
      displayName: user[0].display_name,
      email: user[0].email,
      photoURL: user[0].photo_url,
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// Root route
app.get("/", (req, res) => {
  res.send("Welcome to the Job Portal API!");
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something went wrong!" });
});

// Initialize and start server
initializeDbAndServer();