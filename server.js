const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const { parse } = require("csv-parse/sync");

const app = express();
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});
const upload = multer({ dest: "uploads/" });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret-in-production",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", maxAge: 1000 * 60 * 60 * 4 }
}));
app.use(express.static("public"));

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','student')),
      name TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS exams (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      duration_minutes INTEGER NOT NULL,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS questions (
      id SERIAL PRIMARY KEY,
      exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
      question TEXT NOT NULL,
      option_a TEXT NOT NULL,
      option_b TEXT NOT NULL,
      option_c TEXT NOT NULL,
      option_d TEXT NOT NULL,
      answer TEXT NOT NULL CHECK(answer IN ('A','B','C','D')),
      marks INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS attempts (
      id SERIAL PRIMARY KEY,
      exam_id INTEGER NOT NULL REFERENCES exams(id) ON DELETE CASCADE,
      student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      started_at BIGINT NOT NULL,
      submitted_at BIGINT,
      score INTEGER DEFAULT 0,
      UNIQUE(exam_id, student_id)
    );
    CREATE TABLE IF NOT EXISTS answers (
      id SERIAL PRIMARY KEY,
      attempt_id INTEGER NOT NULL REFERENCES attempts(id) ON DELETE CASCADE,
      question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
      selected TEXT,
      UNIQUE(attempt_id, question_id)
    );
  `);

  const admin = await pool.query("SELECT id FROM users WHERE role='admin' LIMIT 1");
  if (admin.rowCount === 0) {
    const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD || "Admin@123", 12);
    await pool.query(
      "INSERT INTO users(username,password_hash,role,name) VALUES($1,$2,$3,$4)",
      ["admin", hash, "admin", "Administrator"]
    );
  }
}

function auth(role) {
  return (req, res, next) => {
    if (!req.session.user || (role && req.session.user.role !== role)) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    next();
  };
}

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const r = await pool.query("SELECT * FROM users WHERE username=$1", [username]);
    const u = r.rows[0];
    if (!u || !bcrypt.compareSync(password, u.password_hash)) {
      return res.status(401).json({ error: "Invalid username or password" });
    }
    req.session.user = { id: u.id, username: u.username, role: u.role, name: u.name };
    res.json({ user: req.session.user });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/logout", (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get("/api/me", (req, res) => res.json({ user: req.session.user || null }));

app.get("/api/admin/students", auth("admin"), async (req, res) => {
  const r = await pool.query("SELECT id,username,name FROM users WHERE role='student' ORDER BY id DESC");
  res.json(r.rows);
});

app.post("/api/admin/students", auth("admin"), async (req, res) => {
  const { username, password, name } = req.body;
  if (!username || !password || !name) return res.status(400).json({ error: "All fields are required" });
  try {
    const hash = bcrypt.hashSync(password, 12);
    const r = await pool.query(
      "INSERT INTO users(username,password_hash,role,name) VALUES($1,$2,$3,$4) RETURNING id",
      [username, hash, "student", name]
    );
    res.json({ id: r.rows[0].id });
  } catch (e) {
    res.status(400).json({ error: "Username already exists" });
  }
});

app.get("/api/admin/exams", auth("admin"), async (req, res) => {
  const r = await pool.query(`
    SELECT e.id, e.title, e.duration_minutes, e.created_at, COUNT(q.id)::int AS question_count
    FROM exams e LEFT JOIN questions q ON q.exam_id=e.id
    GROUP BY e.id ORDER BY e.id DESC`);
  res.json(r.rows);
});

app.post("/api/admin/exams", auth("admin"), async (req, res) => {
  const { title, duration_minutes } = req.body;
  if (!title || !duration_minutes) return res.status(400).json({ error: "Title and duration are required" });
  const r = await pool.query(
    "INSERT INTO exams(title,duration_minutes) VALUES($1,$2) RETURNING id",
    [title, Number(duration_minutes)]
  );
  res.json({ id: r.rows[0].id });
});

app.post("/api/admin/questions/upload", auth("admin"), upload.single("file"), async (req, res) => {
  const client = await pool.connect();
  try {
    const examId = Number(req.body.exam_id);
    if (!examId || !req.file) return res.status(400).json({ error: "Exam and CSV file are required" });
    const content = fs.readFileSync(req.file.path, "utf8");
    const rows = parse(content, { columns: true, skip_empty_lines: true, trim: true });
    await client.query("BEGIN");
    let count = 0;
    for (const row of rows) {
      const answer = String(row.answer || "").trim().toUpperCase();
      if (!row.question || !row.option_a || !row.option_b || !row.option_c || !row.option_d || !["A","B","C","D"].includes(answer)) {
        throw new Error("CSV must contain question, option_a, option_b, option_c, option_d, answer(A/B/C/D), marks");
      }
      await client.query(`
        INSERT INTO questions(exam_id,question,option_a,option_b,option_c,option_d,answer,marks)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,
        [examId, row.question, row.option_a, row.option_b, row.option_c, row.option_d, answer, Number(row.marks || 1)]
      );
      count++;
    }
    await client.query("COMMIT");
    fs.unlinkSync(req.file.path);
    res.json({ inserted: count });
  } catch (e) {
    await client.query("ROLLBACK").catch(() => {});
    if (req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(400).json({ error: e.message });
  } finally {
    client.release();
  }
});

app.get("/api/admin/results", auth("admin"), async (req, res) => {
  const r = await pool.query(`
    SELECT a.id, e.title, u.username, u.name, a.score, a.started_at, a.submitted_at,
           (SELECT COUNT(*) FROM questions q WHERE q.exam_id=e.id)::int AS question_count
    FROM attempts a JOIN exams e ON e.id=a.exam_id JOIN users u ON u.id=a.student_id
    WHERE a.submitted_at IS NOT NULL ORDER BY a.submitted_at DESC`);
  res.json(r.rows);
});

app.get("/api/student/exams", auth("student"), async (req, res) => {
  const r = await pool.query(`
    SELECT e.id, e.title, e.duration_minutes, COUNT(q.id)::int AS question_count,
           a.id AS attempt_id, a.submitted_at, a.score
    FROM exams e LEFT JOIN questions q ON q.exam_id=e.id
    LEFT JOIN attempts a ON a.exam_id=e.id AND a.student_id=$1
    GROUP BY e.id, a.id ORDER BY e.id DESC`, [req.session.user.id]);
  res.json(r.rows);
});

app.post("/api/student/exams/:id/start", auth("student"), async (req, res) => {
  try {
    const examR = await pool.query("SELECT * FROM exams WHERE id=$1", [req.params.id]);
    const exam = examR.rows[0];
    if (!exam) return res.status(404).json({ error: "Exam not found" });

    let attemptR = await pool.query("SELECT * FROM attempts WHERE exam_id=$1 AND student_id=$2", [exam.id, req.session.user.id]);
    let attempt = attemptR.rows[0];
    if (attempt && attempt.submitted_at) return res.status(400).json({ error: "Exam already submitted" });

    if (!attempt) {
      const r = await pool.query(
        "INSERT INTO attempts(exam_id,student_id,started_at) VALUES($1,$2,$3) RETURNING *",
        [exam.id, req.session.user.id, Date.now()]
      );
      attempt = r.rows[0];
    }

    const questions = (await pool.query(
      "SELECT id,question,option_a,option_b,option_c,option_d,marks FROM questions WHERE exam_id=$1 ORDER BY id",
      [exam.id]
    )).rows;
    const answers = (await pool.query(
      "SELECT question_id,selected FROM answers WHERE attempt_id=$1",
      [attempt.id]
    )).rows;
    res.json({ exam, attempt, questions, answers });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/student/attempts/:id/answer", auth("student"), async (req, res) => {
  try {
    const ar = await pool.query("SELECT * FROM attempts WHERE id=$1 AND student_id=$2", [req.params.id, req.session.user.id]);
    const attempt = ar.rows[0];
    if (!attempt || attempt.submitted_at) return res.status(400).json({ error: "Invalid or closed attempt" });

    const exam = (await pool.query("SELECT * FROM exams WHERE id=$1", [attempt.exam_id])).rows[0];
    if (Date.now() > Number(attempt.started_at) + exam.duration_minutes * 60000) {
      return res.status(400).json({ error: "Time expired" });
    }

    const q = (await pool.query("SELECT id FROM questions WHERE id=$1 AND exam_id=$2", [req.body.question_id, attempt.exam_id])).rows[0];
    if (!q) return res.status(400).json({ error: "Invalid question" });

    await pool.query(`
      INSERT INTO answers(attempt_id,question_id,selected) VALUES($1,$2,$3)
      ON CONFLICT(attempt_id,question_id) DO UPDATE SET selected=EXCLUDED.selected`,
      [attempt.id, q.id, req.body.selected || null]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/student/attempts/:id/submit", auth("student"), async (req, res) => {
  try {
    const ar = await pool.query("SELECT * FROM attempts WHERE id=$1 AND student_id=$2", [req.params.id, req.session.user.id]);
    const attempt = ar.rows[0];
    if (!attempt || attempt.submitted_at) return res.status(400).json({ error: "Invalid or already submitted" });

    const scoreR = await pool.query(`
      SELECT COALESCE(SUM(CASE WHEN ans.selected=q.answer THEN q.marks ELSE 0 END),0)::int AS score
      FROM questions q LEFT JOIN answers ans ON ans.question_id=q.id AND ans.attempt_id=$1
      WHERE q.exam_id=$2`, [attempt.id, attempt.exam_id]);
    const score = scoreR.rows[0].score;

    await pool.query("UPDATE attempts SET submitted_at=$1,score=$2 WHERE id=$3", [Date.now(), score, attempt.id]);
    res.json({ score });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

app.get("/api/student/results", auth("student"), async (req, res) => {
  const r = await pool.query(`
    SELECT e.title,a.score,a.submitted_at,COUNT(q.id)::int AS question_count
    FROM attempts a JOIN exams e ON e.id=a.exam_id
    LEFT JOIN questions q ON q.exam_id=e.id
    WHERE a.student_id=$1 AND a.submitted_at IS NOT NULL
    GROUP BY a.id,e.id ORDER BY a.submitted_at DESC`, [req.session.user.id]);
  res.json(r.rows);
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

const PORT = process.env.PORT || 3000;
initDb()
  .then(() => app.listen(PORT, "0.0.0.0", () => console.log("Exam portal running on port " + PORT)))
  .catch(err => { console.error("Database initialization failed:", err); process.exit(1); });
