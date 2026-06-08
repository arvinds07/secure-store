const express = require("express");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = 5000;
const SECRET = "secret123";
const DB_FILE = "database.json";

app.use(cors());
app.use(express.json());

if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");
if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], files: [] }, null, 2));
}

function readDB() {
  return JSON.parse(fs.readFileSync(DB_FILE));
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

const upload = multer({
  storage: multer.diskStorage({
    destination: "uploads/",
    filename: (req, file, cb) => cb(null, Date.now() + "-" + file.originalname)
  })
});

function auth(req, res, next) {
  try {
    const token = req.headers.authorization;
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Login first" });
  }
}

app.get("/", (req, res) => {
  res.send(`
<!DOCTYPE html>
<html>
<head>
<title>Secure File Store</title>
<style>
body{font-family:Arial;background:#f2f2f2;padding:20px}
h1{text-align:center}
.box{background:white;padding:20px;margin:15px auto;max-width:450px;border-radius:10px}
input,button{width:100%;padding:12px;margin:7px 0}
button{background:#111;color:white;border:0;cursor:pointer}
.result{background:#eee;padding:10px;margin:10px 0}
</style>
</head>
<body>

<h1>Secure File Store</h1>

<div class="box">
<h2>Register</h2>
<input id="rname" placeholder="Name">
<input id="remail" placeholder="Email">
<input id="rpass" type="password" placeholder="Password">
<button onclick="register()">Register</button>
</div>

<div class="box">
<h2>Login</h2>
<input id="lemail" placeholder="Email">
<input id="lpass" type="password" placeholder="Password">
<button onclick="login()">Login</button>
</div>

<div class="box">
<h2>Upload File</h2>
<input id="title" placeholder="File title">
<input id="file" type="file">
<input id="fpass" maxlength="6" placeholder="6 digit file password">
<button onclick="uploadFile()">Upload</button>
</div>

<div class="box">
<h2>Search File / Profile</h2>
<input id="search" placeholder="Search name or file title">
<button onclick="searchFile()">Search</button>
<div id="results"></div>
</div>

<script>
let token = localStorage.getItem("token");

async function register(){
  const res = await fetch("/register",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({
      name:rname.value,
      email:remail.value,
      password:rpass.value
    })
  });
  const data = await res.json();
  alert(data.message || data.error);
}

async function login(){
  const res = await fetch("/login",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({
      email:lemail.value,
      password:lpass.value
    })
  });
  const data = await res.json();
  if(data.token){
    token = data.token;
    localStorage.setItem("token", token);
    alert("Login success");
  } else alert(data.error);
}

async function uploadFile(){
  if(!token) return alert("Login first");
  if(!file.files[0]) return alert("Select file");
  if(!/^[0-9]{6}$/.test(fpass.value)) return alert("Enter 6 digit password");

  const fd = new FormData();
  fd.append("title", title.value);
  fd.append("filePassword", fpass.value);
  fd.append("file", file.files[0]);

  const res = await fetch("/upload",{
    method:"POST",
    headers:{Authorization:token},
    body:fd
  });
  const data = await res.json();
  alert(data.message || data.error);
}

async function searchFile(){
  const res = await fetch("/search?q=" + search.value);
  const data = await res.json();
  results.innerHTML = "";

  data.forEach(item=>{
    results.innerHTML += \`
      <div class="result">
        <b>\${item.title}</b><br>
        Owner: \${item.owner}<br>
        File: \${item.originalname}<br>
        <input id="p\${item.id}" placeholder="Enter file password">
        <button onclick="downloadFile(\${item.id})">Download</button>
      </div>
    \`;
  });
}

async function downloadFile(id){
  const pass = document.getElementById("p"+id).value;

  const res = await fetch("/download/"+id,{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({password:pass})
  });

  if(!res.ok){
    const data = await res.json();
    return alert(data.error);
  }

  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "file";
  a.click();
}
</script>

</body>
</html>
`);
});

app.post("/register", async (req, res) => {
  const db = readDB();
  const { name, email, password } = req.body;

  if (db.users.find(u => u.email === email)) {
    return res.json({ error: "Email already exists" });
  }

  const hash = await bcrypt.hash(password, 10);
  db.users.push({
    id: Date.now(),
    name,
    email,
    password: hash
  });

  writeDB(db);
  res.json({ message: "Register success" });
});

app.post("/login", async (req, res) => {
  const db = readDB();
  const { email, password } = req.body;

  const user = db.users.find(u => u.email === email);
  if (!user) return res.json({ error: "User not found" });

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.json({ error: "Wrong password" });

  const token = jwt.sign({ id: user.id }, SECRET);
  res.json({ token });
});

app.post("/upload", auth, upload.single("file"), async (req, res) => {
  const db = readDB();
  const { title, filePassword } = req.body;

  if (!/^[0-9]{6}$/.test(filePassword)) {
    return res.json({ error: "Password must be 6 digits" });
  }

  const hash = await bcrypt.hash(filePassword, 10);

  db.files.push({
    id: Date.now(),
    user_id: req.user.id,
    title,
    filename: req.file.filename,
    originalname: req.file.originalname,
    file_password: hash
  });

  writeDB(db);
  res.json({ message: "File uploaded" });
});

app.get("/search", (req, res) => {
  const db = readDB();
  const q = (req.query.q || "").toLowerCase();

  const result = db.files.map(f => {
    const user = db.users.find(u => u.id === f.user_id);
    return {
      id: f.id,
      title: f.title,
      originalname: f.originalname,
      owner: user ? user.name : "Unknown"
    };
  }).filter(f =>
    f.title.toLowerCase().includes(q) ||
    f.owner.toLowerCase().includes(q)
  );

  res.json(result);
});

app.post("/download/:id", async (req, res) => {
  const db = readDB();
  const file = db.files.find(f => f.id == req.params.id);

  if (!file) return res.status(404).json({ error: "File not found" });

  const ok = await bcrypt.compare(req.body.password, file.file_password);
  if (!ok) return res.status(403).json({ error: "Wrong file password" });

  res.download(path.join(__dirname, "uploads", file.filename), file.originalname);
});

app.listen(PORT, () => {
  console.log("Website running: http://localhost:" + PORT);
});
