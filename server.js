const express = require("express");
const multer = require("multer");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const nodemailer = require("nodemailer");

const app = express();

const PORT = process.env.PORT || 5000;
const SECRET = process.env.SECRET || "secret123";
const SESSION_SECRET = process.env.SESSION_SECRET || "session_secret_123";
const DB_FILE = "database.json";
const UPLOAD_DIR = "uploads";

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || "";
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || "";
const GOOGLE_CALLBACK_URL =
  process.env.GOOGLE_CALLBACK_URL ||
  "http://localhost:5000/auth/google/callback";

const EMAIL_USER = process.env.EMAIL_USER || "";
const EMAIL_PASS = process.env.EMAIL_PASS || "";

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use("/uploads", express.static(UPLOAD_DIR));

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify({
    users: [],
    folders: [],
    otps: []
  }, null, 2));
}

function readDB() {
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}

function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

function ensureDBShape(db) {
  if (!db.users) db.users = [];
  if (!db.folders) db.folders = [];
  if (!db.otps) db.otps = [];
  return db;
}

function makeToken(user) {
  return jwt.sign({ id: user.id }, SECRET, { expiresIn: "7d" });
}

function auth(req, res, next) {
  try {
    const token = req.headers.authorization;
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Login first" });
  }
}

function mb(bytes) {
  return (bytes / (1024 * 1024)).toFixed(2);
}

function userStorage(userId) {
  const db = ensureDBShape(readDB());
  let total = 0;

  db.folders
    .filter(f => f.user_id === userId)
    .forEach(folder => {
      folder.files.forEach(file => total += file.size || 0);
    });

  return total;
}

function randomOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTP(email, otp) {
  if (!EMAIL_USER || !EMAIL_PASS) {
    console.log("OTP for", email, "is", otp);
    return true;
  }

  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: EMAIL_USER,
      pass: EMAIL_PASS
    }
  });

  await transporter.sendMail({
    from: `"Secure File Store" <${EMAIL_USER}>`,
    to: email,
    subject: "Your Secure File Store OTP",
    html: `
      <div style="font-family:Arial;padding:20px">
        <h2>Secure File Store Password Reset</h2>
        <p>Your OTP is:</p>
        <h1 style="letter-spacing:4px">${otp}</h1>
        <p>This OTP is valid for 10 minutes.</p>
      </div>
    `
  });

  return true;
}

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR + "/",
    filename: (req, file, cb) => {
      const safeName = file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
      cb(null, Date.now() + "-" + safeName);
    }
  })
});

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser((id, done) => {
  const db = ensureDBShape(readDB());
  const user = db.users.find(u => u.id === id);
  done(null, user || false);
});

if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: GOOGLE_CALLBACK_URL
  }, (accessToken, refreshToken, profile, done) => {
    const email = profile.emails && profile.emails[0] ? profile.emails[0].value : "";
    const verified = profile.emails && profile.emails[0] ? profile.emails[0].verified : true;

    if (!email.endsWith("@gmail.com") || verified === false) {
      return done(null, false);
    }

    const db = ensureDBShape(readDB());
    let user = db.users.find(u => u.email === email);

    if (!user) {
      user = {
        id: Date.now().toString(),
        name: profile.displayName || email.split("@")[0],
        email,
        password: "",
        authType: "google",
        createdAt: new Date().toISOString()
      };
      db.users.push(user);
      writeDB(db);
    }

    return done(null, user);
  }));
}

app.get("/auth/google", (req, res, next) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
    return res.send(`
      <h2>Google Login Not Configured</h2>
      <p>Add GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_CALLBACK_URL in Render Environment.</p>
      <a href="/">Back</a>
    `);
  }
  passport.authenticate("google", {
    scope: ["profile", "email"],
    prompt: "select_account"
  })(req, res, next);
});

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    const token = makeToken(req.user);
    res.send(`
      <script>
        localStorage.setItem("token", "${token}");
        window.location.href = "/";
      </script>
    `);
  }
);

app.get("/", (req, res) => {
  res.send(`<!DOCTYPE html>
<html>
<head>
<title>Secure File Store</title>
<link rel="icon" type="image/jpeg" href="/logo.jpg">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<style>
*{box-sizing:border-box}
body{
  margin:0;
  font-family:Arial;
  background:linear-gradient(135deg,#e0f2fe,#f5f3ff,#fdf2f8);
  color:#111827;
  min-height:100vh;
}
header{
  background:linear-gradient(90deg,#111827,#2563eb,#7c3aed);
  color:white;
  padding:16px 25px;
  display:flex;
  justify-content:space-between;
  align-items:center;
  box-shadow:0 8px 24px #0002;
}
header h2{margin:0}
header button{
  width:auto;
  padding:9px 14px;
  background:white;
  color:#111827;
  border-radius:999px;
  margin-left:6px;
  font-weight:bold;
}
.container{max-width:1120px;margin:26px auto;padding:0 15px}
.box{
  background:rgba(255,255,255,.92);
  backdrop-filter:blur(12px);
  padding:24px;
  margin:18px 0;
  border-radius:22px;
  box-shadow:0 10px 30px #1e293b20;
  border:1px solid #ffffffaa;
}
.authBox{max-width:440px;margin:40px auto}
input,button{
  width:100%;
  padding:14px;
  margin:8px 0;
  border-radius:14px;
  border:1px solid #cbd5e1;
  font-size:15px;
}
input:focus{
  outline:2px solid #60a5fa;
  border-color:#2563eb;
}
button{
  background:linear-gradient(90deg,#2563eb,#7c3aed);
  color:white;
  border:0;
  cursor:pointer;
  font-weight:bold;
}
button:hover{opacity:.92;transform:translateY(-1px)}
.googleBtn{
  background:white;
  color:#111827;
  border:1px solid #cbd5e1;
  box-shadow:0 5px 14px #0001;
}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(235px,1fr));gap:16px}
.folder,.file{
  background:linear-gradient(180deg,#ffffff,#f8fafc);
  padding:16px;
  border-radius:18px;
  border:1px solid #e2e8f0;
  box-shadow:0 6px 16px #0000000e;
}
.thumb{width:100%;height:165px;object-fit:cover;border-radius:14px;background:#ddd}
.video{width:100%;height:165px;border-radius:14px;background:#000}
.small{color:#64748b;font-size:13px}
.hide{display:none}
.success{background:#dcfce7;color:#166534;padding:13px;border-radius:14px;margin:10px 0;border:1px solid #86efac}
.error{background:#fee2e2;color:#991b1b;padding:13px;border-radius:14px;margin:10px 0;border:1px solid #fca5a5}
.danger{background:linear-gradient(90deg,#dc2626,#be123c)}
.storage{background:#e2e8f0;border-radius:20px;overflow:hidden;height:19px}
.storage div{background:linear-gradient(90deg,#22c55e,#2563eb);height:19px;width:0%}
a{text-decoration:none}
.logoCircle{
  width:56px;height:56px;border-radius:18px;
  background:linear-gradient(135deg,#2563eb,#7c3aed);
  display:flex;align-items:center;justify-content:center;color:white;font-size:25px;margin:auto;
}
</style>
</head>

<body>

<header>
  <h2>Secure File Store</h2>
  <div>
    <button onclick="showPage('home')">Home</button>
    <button onclick="showPage('settings')">Settings</button>
    <button onclick="logout()">Logout</button>
  </div>
</header>

<div class="container">

<div id="msg"></div>

<div id="loginPage" class="box authBox">
  <div class="logoCircle">🔐</div>
  <h2 style="text-align:center">Login</h2>
  <a href="/auth/google"><button class="googleBtn">Continue with Google</button></a>
  <input id="lemail" placeholder="Gmail">
  <input id="lpass" type="password" placeholder="Password">
  <button onclick="login()">Login</button>
  <p class="small">New user?</p>
  <button onclick="showAuth('register')">Create Account</button>
  <button onclick="showAuth('forgot')">Forgot Password?</button>
</div>

<div id="registerPage" class="box authBox hide">
  <div class="logoCircle">✨</div>
  <h2 style="text-align:center">Register</h2>
  <a href="/auth/google"><button class="googleBtn">Sign up with Google</button></a>
  <input id="rname" placeholder="Name">
  <input id="remail" placeholder="Gmail">
  <input id="rpass" type="password" placeholder="Password">
  <button onclick="register()">Register</button>
  <button onclick="showAuth('login')">Back to Login</button>
</div>

<div id="forgotPage" class="box authBox hide">
  <div class="logoCircle">🔑</div>
  <h2 style="text-align:center">Forgot Password</h2>
  <input id="femail" placeholder="Enter registered Gmail">
  <button onclick="sendOtp()">Send OTP</button>
  <input id="fotp" placeholder="Enter OTP">
  <input id="fnewpass" type="password" placeholder="New Password">
  <button onclick="resetPassword()">Reset Password</button>
  <button onclick="showAuth('login')">Back to Login</button>
</div>

<div id="homePage" class="hide">

  <div class="box">
    <h2>Search Owner / Folder</h2>
    <input id="searchText" placeholder="Search owner name or folder name">
    <button onclick="searchFolder()">Search</button>
    <div id="searchResults"></div>
  </div>

  <div class="box">
    <h2>My Storage</h2>
    <p><b id="storageText">0 MB used / 1 TB</b></p>
    <div class="storage"><div id="storageBar"></div></div>
  </div>

  <div class="box">
    <h2>Create Folder</h2>
    <input id="folderName" placeholder="Folder name">
    <input id="folderPass" type="password" placeholder="Folder password">
    <button onclick="createFolder()">Create Folder</button>
  </div>

  <div class="box">
    <h2>My Folders</h2>
    <div id="myFolders" class="grid"></div>
  </div>

</div>

<div id="folderPage" class="hide">
  <div class="box">
    <button onclick="showPage('home')">Back</button>
    <h2 id="openFolderName"></h2>
    <p id="openFolderOwner" class="small"></p>

    <div id="ownerUploadBox">
      <input id="uploadFiles" type="file" multiple accept="image/*,video/*">
      <button onclick="uploadToFolder()">Upload Images / Videos</button>
    </div>
  </div>

  <div class="box">
    <h2>Files</h2>
    <div id="folderFiles" class="grid"></div>
  </div>
</div>

<div id="settingsPage" class="hide">
  <div class="box">
    <h2>Settings</h2>
    <p><b>Name:</b> <span id="setName"></span></p>
    <p><b>Email:</b> <span id="setEmail"></span></p>
    <p><b>Storage:</b> <span id="setStorage"></span></p>
    <p><b>Account:</b> Gmail / Google login</p>
  </div>
</div>

</div>

<script>
let token = localStorage.getItem("token");
let currentFolderId = null;

function showMsg(text,type="success"){
  msg.innerHTML = '<div class="'+type+'">'+text+'</div>';
  setTimeout(()=>msg.innerHTML="",3500);
}

function showAuth(type){
  loginPage.classList.add("hide");
  registerPage.classList.add("hide");
  forgotPage.classList.add("hide");

  if(type === "login") loginPage.classList.remove("hide");
  if(type === "register") registerPage.classList.remove("hide");
  if(type === "forgot") forgotPage.classList.remove("hide");
}

function showPage(page){
  loginPage.classList.add("hide");
  registerPage.classList.add("hide");
  forgotPage.classList.add("hide");
  homePage.classList.add("hide");
  folderPage.classList.add("hide");
  settingsPage.classList.add("hide");

  if(!token){
    loginPage.classList.remove("hide");
    return;
  }

  if(page === "home"){
    homePage.classList.remove("hide");
    loadDashboard();
  }

  if(page === "settings"){
    settingsPage.classList.remove("hide");
    loadSettings();
  }

  if(page === "folder"){
    folderPage.classList.remove("hide");
  }
}

async function register(){
  if(!remail.value.endsWith("@gmail.com")){
    return showMsg("Only Gmail allowed","error");
  }

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

  if(data.error) return showMsg(data.error,"error");

  showMsg("Register successful. Login now.","success");
  showAuth("login");
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
    localStorage.setItem("token",token);
    showMsg("Login successful","success");
    showPage("home");
  }else{
    showMsg(data.error || "Login failed","error");
  }
}

async function sendOtp(){
  if(!femail.value.endsWith("@gmail.com")){
    return showMsg("Enter valid Gmail","error");
  }

  const res = await fetch("/forgot/send-otp",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({email:femail.value})
  });

  const data = await res.json();
  if(data.error) return showMsg(data.error,"error");
  showMsg("OTP sent. Check Gmail. Local mode: check terminal.","success");
}

async function resetPassword(){
  const res = await fetch("/forgot/reset",{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({
      email:femail.value,
      otp:fotp.value,
      newPassword:fnewpass.value
    })
  });

  const data = await res.json();
  if(data.error) return showMsg(data.error,"error");
  showMsg("Password reset successful. Login now.","success");
  showAuth("login");
}

function logout(){
  localStorage.removeItem("token");
  token = null;
  currentFolderId = null;
  showMsg("Logout successful","success");
  showAuth("login");
}

async function loadDashboard(){
  const res = await fetch("/dashboard",{
    headers:{Authorization:token}
  });

  const data = await res.json();

  if(data.error){
    logout();
    return;
  }

  storageText.innerText = data.storageMB + " MB used / 1 TB";
  storageBar.style.width = data.storagePercent + "%";

  myFolders.innerHTML = "";

  if(data.folders.length === 0){
    myFolders.innerHTML = "<p>No folders created.</p>";
  }

  data.folders.forEach(folder=>{
    myFolders.innerHTML += '<div class="folder"><h3>📁 '+folder.name+'</h3><p class="small">'+folder.filesCount+' files</p><button onclick="openFolder(\\''+folder.id+'\\')">Open</button><button class="danger" onclick="deleteFolder(\\''+folder.id+'\\')">Delete</button></div>';
  });
}

async function loadSettings(){
  const res = await fetch("/settings",{
    headers:{Authorization:token}
  });

  const data = await res.json();

  if(data.error){
    logout();
    return;
  }

  setName.innerText = data.name;
  setEmail.innerText = data.email;
  setStorage.innerText = data.storageMB + " MB / 1 TB";
}

async function createFolder(){
  if(!folderName.value || !folderPass.value){
    return showMsg("Enter folder name and password","error");
  }

  const res = await fetch("/folder/create",{
    method:"POST",
    headers:{
      "Content-Type":"application/json",
      Authorization:token
    },
    body:JSON.stringify({
      name:folderName.value,
      password:folderPass.value
    })
  });

  const data = await res.json();

  if(data.error) return showMsg(data.error,"error");

  folderName.value = "";
  folderPass.value = "";
  showMsg("Folder created successfully","success");
  loadDashboard();
}

async function searchFolder(){
  const res = await fetch("/search?q=" + searchText.value,{
    headers:{Authorization:token}
  });

  const data = await res.json();
  searchResults.innerHTML = "";

  if(data.length === 0){
    searchResults.innerHTML = "<p>No result found.</p>";
    return;
  }

  data.forEach(folder=>{
    if(folder.isOwner){
      searchResults.innerHTML += '<div class="folder"><h3>📁 '+folder.name+'</h3><p class="small">Owner: '+folder.owner+'</p><p class="small">'+folder.filesCount+' files</p><button onclick="openFolder(\\''+folder.id+'\\')">Open My Folder</button></div>';
    }else{
      searchResults.innerHTML += '<div class="folder"><h3>📁 '+folder.name+'</h3><p class="small">Owner: '+folder.owner+'</p><p class="small">'+folder.filesCount+' files</p><input id="pass_'+folder.id+'" type="password" placeholder="Folder password"><button onclick="unlockFolder(\\''+folder.id+'\\')">Open Folder</button></div>';
    }
  });
}

async function unlockFolder(id){
  const pass = document.getElementById("pass_"+id).value;

  const res = await fetch("/folder/" + id + "/unlock",{
    method:"POST",
    headers:{
      "Content-Type":"application/json",
      Authorization:token
    },
    body:JSON.stringify({password:pass})
  });

  const data = await res.json();

  if(data.error){
    return showMsg("Wrong folder password","error");
  }

  showMsg("Folder opened successfully","success");
  openFolder(id);
}

async function openFolder(id){
  currentFolderId = id;

  const res = await fetch("/folder/" + id,{
    headers:{Authorization:token}
  });

  const data = await res.json();

  if(data.error){
    return showMsg(data.error,"error");
  }

  showPage("folder");

  openFolderName.innerText = "📁 " + data.name;
  openFolderOwner.innerText = "Owner: " + data.owner;

  if(data.isOwner){
    ownerUploadBox.classList.remove("hide");
  }else{
    ownerUploadBox.classList.add("hide");
  }

  folderFiles.innerHTML = "";

  if(data.files.length === 0){
    folderFiles.innerHTML = "<p>No files uploaded.</p>";
  }

  data.files.forEach(file=>{
    let preview = "";

    if(file.type.startsWith("image/")){
      preview = '<img class="thumb" src="/uploads/'+file.filename+'">';
    }else if(file.type.startsWith("video/")){
      preview = '<video class="video" controls src="/uploads/'+file.filename+'"></video>';
    }else{
      preview = '<div class="thumb" style="display:flex;align-items:center;justify-content:center">File</div>';
    }

    folderFiles.innerHTML += '<div class="file">'+preview+'<p><b>'+file.originalname+'</b></p><p class="small">'+file.sizeMB+' MB</p><a href="/download/'+data.id+'/'+file.id+'"><button>Download</button></a></div>';
  });
}

async function uploadToFolder(){
  if(!currentFolderId) return showMsg("Open folder first","error");
  if(uploadFiles.files.length === 0) return showMsg("Select image/video","error");

  const fd = new FormData();

  for(let i=0;i<uploadFiles.files.length;i++){
    fd.append("files", uploadFiles.files[i]);
  }

  const res = await fetch("/folder/" + currentFolderId + "/upload",{
    method:"POST",
    headers:{Authorization:token},
    body:fd
  });

  const data = await res.json();

  if(data.error) return showMsg(data.error,"error");

  uploadFiles.value = "";
  showMsg("Files uploaded successfully","success");
  openFolder(currentFolderId);
}

async function deleteFolder(id){
  if(!confirm("Delete this folder?")) return;

  const res = await fetch("/folder/" + id + "/delete",{
    method:"DELETE",
    headers:{Authorization:token}
  });

  const data = await res.json();

  if(data.error) return showMsg(data.error,"error");

  showMsg("Folder deleted successfully","success");
  loadDashboard();
}

if(token){
  showPage("home");
}else{
  showAuth("login");
}
</script>

</body>
</html>`);
});

app.post("/register", async (req, res) => {
  const db = ensureDBShape(readDB());
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.json({ error: "All fields required" });
  }

  if (!email.endsWith("@gmail.com")) {
    return res.json({ error: "Only Gmail allowed" });
  }

  if (db.users.find(u => u.email === email)) {
    return res.json({ error: "Email already exists" });
  }

  const hash = await bcrypt.hash(password, 10);

  db.users.push({
    id: Date.now().toString(),
    name,
    email,
    password: hash,
    authType: "local",
    createdAt: new Date().toISOString()
  });

  writeDB(db);
  res.json({ message: "Register success" });
});

app.post("/login", async (req, res) => {
  const db = ensureDBShape(readDB());
  const { email, password } = req.body;

  const user = db.users.find(u => u.email === email);
  if (!user) return res.json({ error: "User not found" });

  if (!user.password) {
    return res.json({ error: "This account uses Google login" });
  }

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.json({ error: "Wrong password" });

  const token = makeToken(user);
  res.json({ token });
});

app.post("/forgot/send-otp", async (req, res) => {
  const db = ensureDBShape(readDB());
  const { email } = req.body;

  if (!email || !email.endsWith("@gmail.com")) {
    return res.json({ error: "Valid Gmail required" });
  }

  const user = db.users.find(u => u.email === email);
  if (!user) return res.json({ error: "Email not registered" });

  if (!user.password) {
    return res.json({ error: "Google login account cannot reset password here" });
  }

  const otp = randomOTP();
  const expiresAt = Date.now() + 10 * 60 * 1000;

  db.otps = db.otps.filter(o => o.email !== email);
  db.otps.push({ email, otp, expiresAt });

  writeDB(db);

  try {
    await sendOTP(email, otp);
    res.json({ message: "OTP sent" });
  } catch (err) {
    console.log(err);
    res.json({ error: "OTP email failed. Check EMAIL_USER and EMAIL_PASS" });
  }
});

app.post("/forgot/reset", async (req, res) => {
  const db = ensureDBShape(readDB());
  const { email, otp, newPassword } = req.body;

  if (!email || !otp || !newPassword) {
    return res.json({ error: "All fields required" });
  }

  const record = db.otps.find(o => o.email === email && o.otp === otp);

  if (!record) return res.json({ error: "Invalid OTP" });
  if (Date.now() > record.expiresAt) return res.json({ error: "OTP expired" });

  const user = db.users.find(u => u.email === email);
  if (!user) return res.json({ error: "User not found" });

  user.password = await bcrypt.hash(newPassword, 10);
  db.otps = db.otps.filter(o => o.email !== email);

  writeDB(db);
  res.json({ message: "Password reset success" });
});

app.get("/dashboard", auth, (req, res) => {
  const db = ensureDBShape(readDB());
  const user = db.users.find(u => u.id === req.user.id);

  if (!user) return res.json({ error: "User not found" });

  const used = userStorage(user.id);
  const oneTB = 1024 * 1024 * 1024 * 1024;

  const folders = db.folders
    .filter(f => f.user_id === user.id)
    .map(f => ({
      id: f.id,
      name: f.name,
      filesCount: f.files.length
    }));

  res.json({
    name: user.name,
    email: user.email,
    storageMB: mb(used),
    storagePercent: Math.min((used / oneTB) * 100, 100),
    folders
  });
});

app.get("/settings", auth, (req, res) => {
  const db = ensureDBShape(readDB());
  const user = db.users.find(u => u.id === req.user.id);

  if (!user) return res.json({ error: "User not found" });

  res.json({
    name: user.name,
    email: user.email,
    storageMB: mb(userStorage(user.id))
  });
});

app.post("/folder/create", auth, async (req, res) => {
  const db = ensureDBShape(readDB());
  const { name, password } = req.body;

  if (!name || !password) {
    return res.json({ error: "Folder name and password required" });
  }

  const user = db.users.find(u => u.id === req.user.id);
  if (!user) return res.json({ error: "User not found" });

  const hash = await bcrypt.hash(password, 10);

  db.folders.push({
    id: Date.now().toString(),
    user_id: user.id,
    owner: user.name,
    name,
    password: hash,
    files: [],
    unlockedUsers: [],
    createdAt: new Date().toISOString()
  });

  writeDB(db);
  res.json({ message: "Folder created" });
});

app.get("/search", auth, (req, res) => {
  const db = ensureDBShape(readDB());
  const q = (req.query.q || "").toLowerCase();

  const folders = db.folders
    .filter(f =>
      f.name.toLowerCase().includes(q) ||
      f.owner.toLowerCase().includes(q)
    )
    .map(f => ({
      id: f.id,
      name: f.name,
      owner: f.owner,
      filesCount: f.files.length,
      isOwner: f.user_id === req.user.id
    }));

  res.json(folders);
});

app.post("/folder/:id/unlock", auth, async (req, res) => {
  const db = ensureDBShape(readDB());
  const folder = db.folders.find(f => f.id === req.params.id);

  if (!folder) return res.json({ error: "Folder not found" });

  if (folder.user_id === req.user.id) {
    return res.json({ message: "Owner access" });
  }

  const ok = await bcrypt.compare(req.body.password || "", folder.password);

  if (!ok) return res.status(403).json({ error: "Wrong folder password" });

  if (!folder.unlockedUsers.includes(req.user.id)) {
    folder.unlockedUsers.push(req.user.id);
  }

  writeDB(db);
  res.json({ message: "Folder unlocked" });
});

app.get("/folder/:id", auth, (req, res) => {
  const db = ensureDBShape(readDB());
  const folder = db.folders.find(f => f.id === req.params.id);

  if (!folder) return res.json({ error: "Folder not found" });

  const isOwner = folder.user_id === req.user.id;
  const unlocked = folder.unlockedUsers.includes(req.user.id);

  if (!isOwner && !unlocked) {
    return res.status(403).json({ error: "Enter folder password first" });
  }

  res.json({
    id: folder.id,
    name: folder.name,
    owner: folder.owner,
    isOwner,
    files: folder.files.map(file => ({
      id: file.id,
      originalname: file.originalname,
      filename: file.filename,
      type: file.type,
      sizeMB: mb(file.size)
    }))
  });
});

app.post("/folder/:id/upload", auth, upload.array("files", 100), (req, res) => {
  const db = ensureDBShape(readDB());
  const folder = db.folders.find(f => f.id === req.params.id);

  if (!folder) return res.json({ error: "Folder not found" });

  if (folder.user_id !== req.user.id) {
    return res.status(403).json({ error: "Only owner can upload" });
  }

  req.files.forEach(file => {
    folder.files.push({
      id: Date.now().toString() + Math.random().toString(16).slice(2),
      originalname: file.originalname,
      filename: file.filename,
      type: file.mimetype,
      size: file.size,
      uploadedAt: new Date().toISOString()
    });
  });

  writeDB(db);
  res.json({ message: "Files uploaded" });
});

app.get("/download/:folderId/:fileId", auth, (req, res) => {
  const db = ensureDBShape(readDB());
  const folder = db.folders.find(f => f.id === req.params.folderId);

  if (!folder) return res.status(404).send("Folder not found");

  const isOwner = folder.user_id === req.user.id;
  const unlocked = folder.unlockedUsers.includes(req.user.id);

  if (!isOwner && !unlocked) {
    return res.status(403).send("Folder locked");
  }

  const file = folder.files.find(f => f.id === req.params.fileId);

  if (!file) return res.status(404).send("File not found");

  res.download(path.join(__dirname, UPLOAD_DIR, file.filename), file.originalname);
});

app.delete("/folder/:id/delete", auth, (req, res) => {
  const db = ensureDBShape(readDB());
  const folder = db.folders.find(f => f.id === req.params.id);

  if (!folder) return res.json({ error: "Folder not found" });

  if (folder.user_id !== req.user.id) {
    return res.status(403).json({ error: "Only owner can delete" });
  }

  folder.files.forEach(file => {
    const filePath = path.join(__dirname, UPLOAD_DIR, file.filename);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  });

  db.folders = db.folders.filter(f => f.id !== folder.id);

  writeDB(db);
  res.json({ message: "Folder deleted" });
});

app.listen(PORT, () => {
  console.log("Website running: http://localhost:" + PORT);
});
