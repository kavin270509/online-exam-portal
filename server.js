const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { Pool } = require("pg");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const { parse } = require("csv-parse/sync");

const app = express();
const db = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
const upload = multer({ dest: "uploads/" });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || "change-this-secret-in-production",
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax", maxAge: 1000*60*60*4 }
}));
app.use(express.static("public"));

await db.query(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL CHECK(role IN ('admin','student')),
 name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS exams (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 title TEXT NOT NULL,
 duration_minutes INTEGER NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS questions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 exam_id INTEGER NOT NULL,
 question TEXT NOT NULL,
 option_a TEXT NOT NULL,
 option_b TEXT NOT NULL,
 option_c TEXT NOT NULL,
 option_d TEXT NOT NULL,
 answer TEXT NOT NULL CHECK(answer IN ('A','B','C','D')),
 marks INTEGER NOT NULL DEFAULT 1,
 FOREIGN KEY(exam_id) REFERENCES exams(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS attempts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 exam_id INTEGER NOT NULL,
 student_id INTEGER NOT NULL,
 started_at INTEGER NOT NULL,
 submitted_at INTEGER,
 score INTEGER DEFAULT 0,
 UNIQUE(exam_id, student_id)
);
CREATE TABLE IF NOT EXISTS answers (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 attempt_id INTEGER NOT NULL,
 question_id INTEGER NOT NULL,
 selected TEXT,
 UNIQUE(attempt_id, question_id)
);
`);

const admin = (await db.query("SELECT id FROM users WHERE role='admin' LIMIT 1")).rows[0];
if (!admin) {
  const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD || "Admin@123", 12);
  await db.query("INSERT INTO users(username,password_hash,role,name) VALUES($1,$2,$3,$4)",["admin", hash, "admin", "Administrator"]);
}

function auth(role) {
  return (req,res,next) => {
    if (!req.session.user || (role && req.session.user.role !== role))
      return res.status(401).json({error:"Unauthorized"});
    next();
  };
}

app.post("/api/login", async async (req,res)=>{
  const {username,password} = req.body;
  const u = (await db.query("SELECT * FROM users WHERE username=$1", [username])).rows[0];
  if (!u || !bcrypt.compareSync(password,u.password_hash))
    return res.status(401).json({error:"Invalid username or password"});
  req.session.user = {id:u.id, username:u.username, role:u.role, name:u.name};
  res.json({user:req.session.user});
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({user:req.session.user||null}));

app.get("/api/admin/students",auth("admin"),async (req,res)=>{
  res.json((await db.query("SELECT id,username,name FROM users WHERE role='student' ORDER BY id DESC", [])).rows);
});
app.post("/api/admin/students",auth("admin"),async (req,res)=>{
  const {username,password,name} = req.body;
  if (!username || !password || !name) return res.status(400).json({error:"All fields are required"});
  try {
    const hash=bcrypt.hashSync(password,12);
    const r=db.query("INSERT INTO users(username,password_hash,role,name) VALUES($1,$2,$3,$4)")
      ); /*RUN*/ db.query(username,hash,"student",name);
    res.json({id:r.lastInsertRowid});
  } catch(e){res.status(400).json({error:"Username already exists"});}
});

app.get("/api/admin/exams",auth("admin"),async (req,res)=>{
  res.json((await db.query(`
    SELECT e.*, COUNT(q.id) question_count
    FROM exams e LEFT JOIN questions q ON q.exam_id=e.id
    GROUP BY e.id ORDER BY e.id DESC`, [])).rows);
});
app.post("/api/admin/exams",auth("admin"),async (req,res)=>{
  const {title,duration_minutes} = req.body;
  if(!title || !duration_minutes) return res.status(400).json({error:"Title and duration are required"});
  const r=db.query("INSERT INTO exams(title,duration_minutes) VALUES($1,$2)")); /*RUN*/ db.query(title,Number(duration_minutes));
  res.json({id:r.lastInsertRowid});
});

app.post("/api/admin/questions/upload",auth("admin"),upload.single("file"),async (req,res)=>{
  try {
    const examId=Number(req.body.exam_id);
    if(!examId || !req.file) return res.status(400).json({error:"Exam and CSV file are required"});
    const content=fs.readFileSync(req.file.path,"utf8");
    const rows=parse(content,{columns:true,skip_empty_lines:true,trim:true});
    const insert=db.query(`INSERT INTO questions
      (exam_id,question,option_a,option_b,option_c,option_d,answer,marks)
      VALUES($1,$2,$3,$4,$5,$6,$7,$8)`);
    const tx=db.transaction(rows=>{
      let n=0;
      for(const r of rows){
        const answer=String(r.answer||"").toUpperCase();
        if(!r.question||!r.option_a||!r.option_b||!r.option_c||!r.option_d||!["A","B","C","D"].includes(answer))
          throw new Error("CSV must contain question, option_a, option_b, option_c, option_d, answer(A/B/C/D), marks");
        insert); /*RUN*/ db.query(examId,r.question,r.option_a,r.option_b,r.option_c,r.option_d,answer,Number(r.marks||1)); n++;
      } return n;
    });
    const count=tx(rows);
    fs.unlinkSync(req.file.path);
    res.json({inserted:count});
  } catch(e) {
    if(req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
    res.status(400).json({error:e.message});
  }
});

app.get("/api/admin/results",auth("admin"),async (req,res)=>{
  res.json((await db.query(`
    SELECT a.id, e.title, u.username, u.name, a.score, a.started_at, a.submitted_at,
           (SELECT COUNT(*) FROM questions q WHERE q.exam_id=e.id) question_count
    FROM attempts a JOIN exams e ON e.id=a.exam_id JOIN users u ON u.id=a.student_id
    WHERE a.submitted_at IS NOT NULL ORDER BY a.submitted_at DESC`, [])).rows);
});

app.get("/api/student/exams",auth("student"),async (req,res)=>{
  res.json((await db.query(`
    SELECT e.id,e.title,e.duration_minutes,COUNT(q.id) question_count,
    a.id attempt_id,a.submitted_at,a.score
    FROM exams e LEFT JOIN questions q ON q.exam_id=e.id
    LEFT JOIN attempts a ON a.exam_id=e.id AND a.student_id=$2
    GROUP BY e.id ORDER BY e.id DESC`, [req.session.user.id])).rows);
});

app.post("/api/student/exams/:id/start",auth("student"),async (req,res)=>{
  const exam=db.query("SELECT * FROM exams WHERE id=$1").get(req.params.id);
  if(!exam) return res.status(404).json({error:"Exam not found"});
  let attempt=db.query("SELECT * FROM attempts WHERE exam_id=$1 AND student_id=$2").get(exam.id,req.session.user.id);
  if(attempt && attempt.submitted_at) return res.status(400).json({error:"Exam already submitted"});
  if(!attempt){
    const r=db.query("INSERT INTO attempts(exam_id,student_id,started_at) VALUES($1,$2,$3)")
      ); /*RUN*/ db.query(exam.id,req.session.user.id,Date.now());
    attempt=db.query("SELECT * FROM attempts WHERE id=$1").get(r.lastInsertRowid);
  }
  const questions=(await db.query("SELECT id,question,option_a,option_b,option_c,option_d,marks FROM questions WHERE exam_id=$1 ORDER BY id", [exam.id])).rows;
  const existing=(await db.query("SELECT question_id,selected FROM answers WHERE attempt_id=?", [attempt.id])).rows;
  res.json({exam,attempt,questions,answers:existing});
});

app.post("/api/student/attempts/:id/answer",auth("student"),async (req,res)=>{
  const a=db.query("SELECT * FROM attempts WHERE id=$1 AND student_id=$2").get(req.params.id,req.session.user.id);
  if(!a || a.submitted_at) return res.status(400).json({error:"Invalid or closed attempt"});
  const exam=db.query("SELECT * FROM exams WHERE id=$1").get(a.exam_id);
  if(Date.now() > a.started_at + exam.duration_minutes*60000) return res.status(400).json({error:"Time expired"});
  const q=db.query("SELECT id FROM questions WHERE id=$1 AND exam_id=$1").get(req.body.question_id,a.exam_id);
  if(!q) return res.status(400).json({error:"Invalid question"});
  db.query(`INSERT INTO answers(attempt_id,question_id,selected) VALUES($1,$2,$3)
    ON CONFLICT(attempt_id,question_id) DO UPDATE SET selected=excluded.selected`)
    ); /*RUN*/ db.query(a.id,q.id,req.body.selected||null);
  res.json({ok:true});
});

app.post("/api/student/attempts/:id/submit",auth("student"),async (req,res)=>{
  const a=db.query("SELECT * FROM attempts WHERE id=$1 AND student_id=$2").get(req.params.id,req.session.user.id);
  if(!a || a.submitted_at) return res.status(400).json({error:"Invalid or already submitted"});
  const score=db.query(`
    SELECT COALESCE(SUM(CASE WHEN ans.selected=q.answer THEN q.marks ELSE 0 END),0) score
    FROM questions q LEFT JOIN answers ans ON ans.question_id=q.id AND ans.attempt_id=?
    WHERE q.exam_id=$1`).get(a.id,a.exam_id).score;
  db.query("UPDATE attempts SET submitted_at=?,score=? WHERE id=$1")); /*RUN*/ db.query(Date.now(),score,a.id);
  res.json({score});
});

app.get("/api/student/results",auth("student"),async (req,res)=>{
  res.json((await db.query(`
    SELECT e.title,a.score,a.submitted_at,COUNT(q.id) question_count
    FROM attempts a JOIN exams e ON e.id=a.exam_id
    LEFT JOIN questions q ON q.exam_id=e.id
    WHERE a.student_id=$2 AND a.submitted_at IS NOT NULL GROUP BY a.id`, [req.session.user.id])).rows);
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"public","index.html")));
app.listen(process.env.PORT||3000,()=>console.log("Exam portal running on http://localhost:"+(process.env.PORT||3000)));
