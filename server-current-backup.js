const express=require("express");
const multer=require("multer");
const bcrypt=require("bcryptjs");
const jwt=require("jsonwebtoken");
const cors=require("cors");
const fs=require("fs");
const path=require("path");
const session=require("express-session");
const passport=require("passport");
const GoogleStrategy=require("passport-google-oauth20").Strategy;
const nodemailer=require("nodemailer");

const app=express();
const PORT=process.env.PORT||5000;
const SECRET=process.env.SECRET||"secret123";
const SESSION_SECRET=process.env.SESSION_SECRET||"session_secret_123";
const DB_FILE="database.json";
const UPLOAD_DIR="uploads";
const GOOGLE_CLIENT_ID=process.env.GOOGLE_CLIENT_ID||"";
const GOOGLE_CLIENT_SECRET=process.env.GOOGLE_CLIENT_SECRET||"";
const GOOGLE_CALLBACK_URL=process.env.GOOGLE_CALLBACK_URL||"http://localhost:5000/auth/google/callback";
const EMAIL_USER=process.env.EMAIL_USER||"";
const EMAIL_PASS=process.env.EMAIL_PASS||"";

app.use(cors());
app.use(express.json({limit:"20mb"}));
app.use(express.urlencoded({extended:true,limit:"20mb"}));
app.use(express.static("public"));
app.use("/uploads",express.static(UPLOAD_DIR));
app.use(session({secret:SESSION_SECRET,resave:false,saveUninitialized:false}));
app.use(passport.initialize());
app.use(passport.session());

if(!fs.existsSync(UPLOAD_DIR))fs.mkdirSync(UPLOAD_DIR);
if(!fs.existsSync(DB_FILE))fs.writeFileSync(DB_FILE,JSON.stringify({users:[],folders:[],otps:[]},null,2));

function readDB(){return JSON.parse(fs.readFileSync(DB_FILE,"utf8"))}
function writeDB(d){fs.writeFileSync(DB_FILE,JSON.stringify(d,null,2))}
function shape(d){if(!d.users)d.users=[];if(!d.folders)d.folders=[];if(!d.otps)d.otps=[];return d}
function validGmail(e){return /^[a-zA-Z0-9._%+-]+@gmail\.com$/.test(String(e||"").trim().toLowerCase())}
function tokenFor(u){return jwt.sign({id:u.id},SECRET,{expiresIn:"7d"})}
function auth(req,res,next){try{req.user=jwt.verify(req.headers.authorization||req.query.token,SECRET);next()}catch{res.status(401).json({error:"Login first"})}}
function mb(b){return (b/1048576).toFixed(2)}
function storage(uid){let db=shape(readDB()),t=0;db.folders.filter(f=>f.user_id===uid).forEach(f=>f.files.forEach(x=>t+=x.size||0));return t}
function otp(){return Math.floor(100000+Math.random()*900000).toString()}

async function sendOTP(email,code){
 if(!EMAIL_USER||!EMAIL_PASS){console.log("OTP for",email,"is",code);return true}
 const tr=nodemailer.createTransport({service:"gmail",auth:{user:EMAIL_USER,pass:EMAIL_PASS}});
 await tr.sendMail({from:`"Secure File Store" <${EMAIL_USER}>`,to:email,subject:"Secure File Store OTP",html:`<h2>Your OTP: ${code}</h2><p>Valid for 10 minutes.</p>`});
}

const upload=multer({
 storage:multer.diskStorage({destination:UPLOAD_DIR+"/",filename:(req,file,cb)=>cb(null,Date.now()+"-"+file.originalname.replace(/[^a-zA-Z0-9._-]/g,"_"))}),
 limits:{fileSize:1024*1024*1024}
});

passport.serializeUser((u,d)=>d(null,u.id));
passport.deserializeUser((id,d)=>{let db=shape(readDB());d(null,db.users.find(u=>u.id===id)||false)});

if(GOOGLE_CLIENT_ID&&GOOGLE_CLIENT_SECRET){
 passport.use(new GoogleStrategy({clientID:GOOGLE_CLIENT_ID,clientSecret:GOOGLE_CLIENT_SECRET,callbackURL:GOOGLE_CALLBACK_URL},(a,r,p,done)=>{
  const email=p.emails?.[0]?.value||"",ver=p.emails?.[0]?.verified!==false;
  if(!validGmail(email)||!ver)return done(null,false);
  let db=shape(readDB()),u=db.users.find(x=>x.email===email);
  if(!u){u={id:Date.now().toString(),name:p.displayName||email.split("@")[0],email,password:"",authType:"google",createdAt:new Date().toISOString()};db.users.push(u);writeDB(db)}
  done(null,u);
 }));
}

app.get("/auth/google",(req,res,next)=>{
 if(!GOOGLE_CLIENT_ID||!GOOGLE_CLIENT_SECRET)return res.send("<h2>Google Login Not Configured</h2><p>Add GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_CALLBACK_URL in Render Environment.</p><a href='/'>Back</a>");
 passport.authenticate("google",{scope:["profile","email"],prompt:"select_account"})(req,res,next)
});
app.get("/auth/google/callback",passport.authenticate("google",{failureRedirect:"/"}),(req,res)=>res.send(`<script>localStorage.setItem("token","${tokenFor(req.user)}");location.href="/";</script>`));

app.get("/manifest.json",(req,res)=>res.json({name:"Secure File Store",short_name:"SecureStore",start_url:"/",display:"standalone",background_color:"#eef2ff",theme_color:"#2563eb",icons:[{src:"/logo.jpg",sizes:"192x192",type:"image/jpeg"},{src:"/logo.jpg",sizes:"512x512",type:"image/jpeg"}]}));
app.get("/sw.js",(req,res)=>res.type("application/javascript").send(`self.addEventListener("install",e=>self.skipWaiting());self.addEventListener("activate",e=>self.clients.claim());self.addEventListener("fetch",e=>e.respondWith(fetch(e.request).catch(()=>caches.match(e.request))));`));

app.get("/",(req,res)=>res.send(`<!doctype html><html><head><title>Secure File Store</title><link rel="icon" href="/logo.jpg"><link rel="manifest" href="/manifest.json"><meta name="theme-color" content="#2563eb"><meta name="viewport" content="width=device-width,initial-scale=1"><style>
*{box-sizing:border-box}:root{--b:#2563eb;--p:#7c3aed;--r:#ec4899;--g:#22c55e;--d:#0f172a;--m:#64748b}body{margin:0;font-family:Arial;background:radial-gradient(circle at 10% 0,#dbeafe,transparent 35%),radial-gradient(circle at 90% 0,#f5d0fe,transparent 30%),linear-gradient(135deg,#eef2ff,#fdf2f8);color:#111827;min-height:100vh}.top{position:sticky;top:0;z-index:9;background:linear-gradient(90deg,#0f172a,#2563eb,#7c3aed,#ec4899);color:white;padding:14px 22px;display:flex;justify-content:space-between;align-items:center;box-shadow:0 8px 24px #0002}.brand{display:flex;align-items:center;gap:10px}.brand img{width:38px;height:38px;border-radius:12px}.top button{width:auto;background:white;color:#111827;border-radius:999px;padding:10px 16px;margin-left:8px}.layout{display:grid;grid-template-columns:260px 1fr;gap:18px;max-width:1300px;margin:24px auto;padding:0 15px}.layout.loginMode{display:block;max-width:760px}.layout.loginMode main{width:100%}.side{position:sticky;top:82px;height:calc(100vh - 105px);background:#ffffffdd;border:1px solid #fff;border-radius:24px;padding:18px;box-shadow:0 10px 30px #0001}.side button{text-align:left;background:#f8fafc;color:#111;border:1px solid #e2e8f0}.box{background:#ffffffe8;padding:24px;margin-bottom:18px;border-radius:24px;box-shadow:0 10px 30px #1e293b18;border:1px solid #fff}.auth{max-width:460px;margin:38px auto}.logo{width:60px;height:60px;border-radius:20px;background:linear-gradient(135deg,var(--b),var(--p),var(--r));display:flex;align-items:center;justify-content:center;color:white;font-size:26px;margin:auto}input,button{width:100%;padding:14px;margin:8px 0;border-radius:15px;border:1px solid #cbd5e1;font-size:15px}button{background:linear-gradient(90deg,var(--b),var(--p));color:white;border:0;cursor:pointer;font-weight:bold}button:disabled{opacity:.55}.google{background:white;color:#111;border:1px solid #cbd5e1}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:14px}.folder,.file{background:linear-gradient(180deg,#fff,#f8fafc);padding:14px;border-radius:20px;border:1px solid #e2e8f0;box-shadow:0 6px 16px #0001;overflow:hidden}.thumb,.vid{width:100%;aspect-ratio:1/1;object-fit:cover;border-radius:16px;background:#e2e8f0;cursor:pointer}.small{color:var(--m);font-size:13px}.hide{display:none!important}.success{background:#dcfce7;color:#166534;padding:13px;border-radius:14px;margin:10px 0;border:1px solid #86efac}.error{background:#fee2e2;color:#991b1b;padding:13px;border-radius:14px;margin:10px 0;border:1px solid #fca5a5}.danger{background:linear-gradient(90deg,#dc2626,#be123c)!important;color:white!important}.storage{background:#e2e8f0;border-radius:20px;overflow:hidden;height:20px}.storage div{background:linear-gradient(90deg,#22c55e,#2563eb,#7c3aed);height:20px;width:0}.drawerO{position:fixed;inset:0;background:#0007;z-index:50;display:none}.drawer{width:25vw;min-width:310px;max-width:420px;height:100%;background:white;padding:24px;box-shadow:10px 0 40px #0003}.avatar{width:70px;height:70px;border-radius:24px;background:linear-gradient(135deg,var(--b),var(--r));color:white;display:flex;align-items:center;justify-content:center;font-size:32px}.modalO{position:fixed;inset:0;background:#000b;z-index:70;display:none;align-items:center;justify-content:center;padding:20px}.modal{width:min(100%,1000px);max-height:90vh;background:white;border-radius:24px;overflow:auto;padding:18px}.modal img,.modal video{max-width:100%;max-height:68vh;display:block;margin:auto;border-radius:18px}.prog{background:#e2e8f0;border-radius:18px;height:22px;overflow:hidden}.bar{background:linear-gradient(90deg,#22c55e,#2563eb,#7c3aed);height:22px;width:0;color:white;text-align:center;font-size:12px;line-height:22px}.install{background:linear-gradient(90deg,#22c55e,#14b8a6)!important;color:white!important}@media(max-width:900px){.layout{grid-template-columns:1fr}.side{position:relative;top:0;height:auto}.drawer{width:85vw}.top button{padding:8px 10px;font-size:13px}}
</style></head><body><div class="top"><div class="brand"><img src="/logo.jpg"><h2>Secure File Store</h2></div><div id="topActions" style="display:none"><button onclick="showPage('home')">Home</button><button onclick="openDrawer()">Profile</button></div></div><div id="mainLayout" class="layout loginMode"><aside id="sideBar" class="side" style="display:none"><button onclick="showPage('home')">🏠 Dashboard</button><button onclick="showPage('myfiles')">🖼️ My Files</button><button onclick="showPage('settings')">⚙️ Settings</button><button class="install" onclick="installApp()">📲 Install App</button><button class="danger" onclick="logout()">🚪 Logout</button><p class="small">Album-style photo and video view is available.</p></aside><main><div id="msg"></div>
<div id="loginPage" class="box auth"><div class="logo">🔐</div><h2 style="text-align:center">Login</h2><a href="/auth/google"><button class="google">Continue with Google</button></a><input id="lemail" placeholder="Valid Gmail"><input id="lpass" type="password" placeholder="Password"><button onclick="login()">Login</button><button onclick="showAuth('register')">Create Account</button><button onclick="showAuth('forgot')">Forgot Password?</button></div>
<div id="registerPage" class="box auth hide"><div class="logo">✨</div><h2 style="text-align:center">Register</h2><a href="/auth/google"><button class="google">Sign up with Google</button></a><input id="rname" placeholder="Name"><input id="remail" placeholder="Valid Gmail only"><input id="rpass" type="password" placeholder="Password"><button onclick="register()">Register</button><button onclick="showAuth('login')">Back to Login</button></div>
<div id="forgotPage" class="box auth hide"><div class="logo">🔑</div><h2 style="text-align:center">Forgot Password</h2><input id="femail" placeholder="Registered Gmail"><button onclick="sendOtp()">Send OTP</button><input id="fotp" placeholder="Enter OTP"><input id="fnewpass" type="password" placeholder="New Password"><button onclick="resetPassword()">Reset Password</button><button onclick="showAuth('login')">Back</button></div>
<div id="homePage" class="hide"><div class="box"><h2>Search Owner / Folder</h2><input id="searchText" placeholder="Search owner name or folder name"><button onclick="searchFolder()">Search</button><div id="searchResults"></div></div><div class="box"><h2>My Storage</h2><p><b id="storageText">0 MB used / 1 TB</b></p><div class="storage"><div id="storageBar"></div></div></div><div class="box"><h2>Create Folder</h2><input id="folderName" placeholder="Folder name"><input id="folderPass" type="password" placeholder="Folder password"><button onclick="createFolder()">Create Folder</button></div><div class="box"><h2>My Folders</h2><div id="myFolders" class="grid"></div></div></div>
<div id="myFilesPage" class="hide"><div class="box"><h2>My Files</h2><div id="allMyFiles" class="grid"></div></div></div>
<div id="folderPage" class="hide"><div class="box"><button onclick="showPage('home')">Back</button><h2 id="openFolderName"></h2><p id="openFolderOwner" class="small"></p><div id="ownerUploadBox"><input id="uploadFiles" type="file" multiple accept="image/*,video/*"><button id="uploadBtn" onclick="uploadToFolder()">Upload Images / Videos</button><div id="uploadProgressWrap" class="prog hide"><div id="uploadProgressBar" class="bar">0%</div></div><p id="uploadInfo" class="small"></p></div></div><div class="box"><h2>Gallery View</h2><div id="folderFiles" class="grid"></div></div></div>
<div id="settingsPage" class="hide"><div class="box"><h2>Settings</h2><p><b>Name:</b> <span id="setName"></span></p><p><b>Email:</b> <span id="setEmail"></span></p><p><b>Storage:</b> <span id="setStorage"></span></p><button class="install" onclick="installApp()">Add to Home Screen</button></div></div>
</main></div><div id="drawerOverlay" class="drawerO" onclick="closeDrawer(event)"><div class="drawer"><div class="avatar" id="drawerAvatar">A</div><h2 id="drawerName">Profile</h2><p><b>Gmail:</b></p><p id="drawerEmail" class="small"></p><p><b>Storage:</b></p><p id="drawerStorage" class="small"></p><hr><button onclick="showPage('settings');drawerOverlay.style.display='none'">Settings</button><button class="danger" onclick="logout()">Logout</button></div></div>
<div id="modalOverlay" class="modalO"><div class="modal"><button onclick="closeViewer()">Close</button><a id="modalDownload" href="#"><button>Download</button></a><h3 id="modalTitle"></h3><div id="modalContent"></div></div></div>
<script>
let token=localStorage.getItem("token"),currentFolderId=null,currentUserData=null,deferredPrompt=null;
window.addEventListener("beforeinstallprompt",e=>{e.preventDefault();deferredPrompt=e});
if("serviceWorker"in navigator)navigator.serviceWorker.register("/sw.js").catch(()=>{});
function installApp(){if(deferredPrompt){deferredPrompt.prompt();deferredPrompt.userChoice.finally(()=>deferredPrompt=null)}else showMsg("Use the browser menu and choose Install app / Add to Home screen.","success")}
function showMsg(t,y="success"){msg.innerHTML='<div class="'+y+'">'+t+'</div>';setTimeout(()=>msg.innerHTML="",3500)}
function setLoggedUI(isLogged){
  var side = document.getElementById("sideBar");
  var top = document.getElementById("topActions");
  var layout = document.getElementById("mainLayout");
  if(isLogged){
    if(side) side.style.display = "block";
    if(top) top.style.display = "block";
    if(layout) layout.classList.remove("loginMode");
  }else{
    if(side) side.style.display = "none";
    if(top) top.style.display = "none";
    if(layout) layout.classList.add("loginMode");
  }
}
function hideAllPages(){
  [loginPage,registerPage,forgotPage,homePage,folderPage,settingsPage,myFilesPage].forEach(x=>x.classList.add("hide"));
}
function showAuth(t){
  setLoggedUI(false);
  hideAllPages();
  if(t==="login")loginPage.classList.remove("hide");
  if(t==="register")registerPage.classList.remove("hide");
  if(t==="forgot")forgotPage.classList.remove("hide");
}
function showPage(p){
  hideAllPages();
  if(!token){
    showAuth("login");
    return;
  }
  setLoggedUI(true);
  if(p==="home"){homePage.classList.remove("hide");loadDashboard()}
  if(p==="settings"){settingsPage.classList.remove("hide");loadSettings()}
  if(p==="folder")folderPage.classList.remove("hide");
  if(p==="myfiles"){myFilesPage.classList.remove("hide");loadMyFiles()}
}
function isG(e){return /^[a-zA-Z0-9._%+-]+@gmail\\.com$/.test(e)}
async function register(){let email=remail.value.trim().toLowerCase();if(!isG(email))return showMsg("Only a valid Gmail address is allowed. Example: name@gmail.com","error");let r=await fetch("/register",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:rname.value.trim(),email,password:rpass.value})});let d=await r.json();if(d.error)return showMsg(d.error,"error");showMsg("Register successful. Login now.");showAuth("login")}
async function login(){let email=lemail.value.trim().toLowerCase();if(!isG(email))return showMsg("Enter a valid Gmail address","error");let r=await fetch("/login",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email,password:lpass.value})});let d=await r.json();if(d.token){token=d.token;localStorage.setItem("token",token);showMsg("Login successful");showPage("home")}else showMsg(d.error||"Login failed","error")}
async function sendOtp(){let email=femail.value.trim().toLowerCase();if(!isG(email))return showMsg("Enter a valid Gmail address","error");let r=await fetch("/forgot/send-otp",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email})});let d=await r.json();if(d.error)return showMsg(d.error,"error");showMsg("OTP sent. If email does not arrive, check Render Logs or local terminal for OTP.")}
async function resetPassword(){let r=await fetch("/forgot/reset",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email:femail.value.trim().toLowerCase(),otp:fotp.value.trim(),newPassword:fnewpass.value})});let d=await r.json();if(d.error)return showMsg(d.error,"error");showMsg("Password reset successful.");showAuth("login")}
function logout(){localStorage.removeItem("token");token=null;currentFolderId=null;currentUserData=null;showMsg("Logout successful");showAuth("login")}
async function loadDashboard(){let r=await fetch("/dashboard",{headers:{Authorization:token}}),d=await r.json();if(d.error){logout();return}currentUserData=d;updateProfileUI();storageText.innerText=d.storageMB+" MB used / 1 TB";storageBar.style.width=d.storagePercent+"%";myFolders.innerHTML=d.folders.length?"":"<p>No folders created.</p>";d.folders.forEach(f=>myFolders.innerHTML+='<div class="folder"><h3>📁 '+f.name+'</h3><p class="small">'+f.filesCount+' files</p><button onclick="openFolder(\\''+f.id+'\\')">View / Open</button><button class="danger" onclick="deleteFolder(\\''+f.id+'\\')">Delete</button></div>')}
function updateProfileUI(){if(!currentUserData)return;drawerName.innerText=currentUserData.name||"User";drawerEmail.innerText=currentUserData.email||"";drawerStorage.innerText=currentUserData.storageMB+" MB / 1 TB";drawerAvatar.innerText=(currentUserData.name||"U")[0].toUpperCase()}
function openDrawer(){if(!token){showAuth("login");return}updateProfileUI();drawerOverlay.style.display="block"}function closeDrawer(e){if(e.target.id==="drawerOverlay")drawerOverlay.style.display="none"}
async function loadSettings(){let r=await fetch("/settings",{headers:{Authorization:token}}),d=await r.json();if(d.error){logout();return}setName.innerText=d.name;setEmail.innerText=d.email;setStorage.innerText=d.storageMB+" MB / 1 TB"}
async function createFolder(){if(!folderName.value||!folderPass.value)return showMsg("Enter folder name and password","error");let r=await fetch("/folder/create",{method:"POST",headers:{"Content-Type":"application/json",Authorization:token},body:JSON.stringify({name:folderName.value,password:folderPass.value})});let d=await r.json();if(d.error)return showMsg(d.error,"error");folderName.value="";folderPass.value="";showMsg("Folder created successfully");loadDashboard()}
async function searchFolder(){let r=await fetch("/search?q="+encodeURIComponent(searchText.value),{headers:{Authorization:token}}),d=await r.json();searchResults.innerHTML="";if(!d.length){searchResults.innerHTML="<p>No result found.</p>";return}d.forEach(f=>{if(f.isOwner)searchResults.innerHTML+='<div class="folder"><h3>📁 '+f.name+'</h3><p class="small">Owner: '+f.owner+'</p><p class="small">'+f.filesCount+' files</p><button onclick="openFolder(\\''+f.id+'\\')">Open My Folder</button></div>';else searchResults.innerHTML+='<div class="folder"><h3>📁 '+f.name+'</h3><p class="small">Owner: '+f.owner+'</p><p class="small">'+f.filesCount+' files</p><input id="pass_'+f.id+'" type="password" placeholder="Folder password"><button onclick="unlockFolder(\\''+f.id+'\\')">View Folder</button></div>'})}
async function unlockFolder(id){let pass=document.getElementById("pass_"+id).value,r=await fetch("/folder/"+id+"/unlock",{method:"POST",headers:{"Content-Type":"application/json",Authorization:token},body:JSON.stringify({password:pass})}),d=await r.json();if(d.error)return showMsg("Wrong folder password","error");showMsg("Folder opened successfully");openFolder(id)}
async function openFolder(id){currentFolderId=id;let r=await fetch("/folder/"+id,{headers:{Authorization:token}}),d=await r.json();if(d.error)return showMsg(d.error,"error");showPage("folder");openFolderName.innerText="📁 "+d.name;openFolderOwner.innerText="Owner: "+d.owner;if(d.isOwner)ownerUploadBox.classList.remove("hide");else ownerUploadBox.classList.add("hide");renderFiles(d.files,d.id,folderFiles)}
function esc(s){return String(s||"").replace(/'/g,"").replace(/"/g,"")}
function renderFiles(files,folderId,target){target.innerHTML=files.length?"":"<p>No files uploaded.</p>";files.forEach(file=>{let p="";if(file.type.startsWith("image/"))p='<img class="thumb" onclick="viewFile(\\''+folderId+'\\',\\''+file.id+'\\',\\''+file.filename+'\\',\\''+esc(file.originalname)+'\\',\\''+file.type+'\\')" src="/uploads/'+file.filename+'">';else if(file.type.startsWith("video/"))p='<video class="vid" onclick="viewFile(\\''+folderId+'\\',\\''+file.id+'\\',\\''+file.filename+'\\',\\''+esc(file.originalname)+'\\',\\''+file.type+'\\')" src="/uploads/'+file.filename+'"></video>';else p='<div class="thumb">File</div>';target.innerHTML+='<div class="file">'+p+'<p><b>'+file.originalname+'</b></p><p class="small">'+file.sizeMB+' MB</p><button onclick="viewFile(\\''+folderId+'\\',\\''+file.id+'\\',\\''+file.filename+'\\',\\''+esc(file.originalname)+'\\',\\''+file.type+'\\')">View</button></div>'})}
function viewFile(folderId,fileId,filename,name,type){modalTitle.innerText=name;modalDownload.href="/download/"+folderId+"/"+fileId+"?token="+encodeURIComponent(token);if(type.startsWith("image/"))modalContent.innerHTML='<img src="/uploads/'+filename+'">';else if(type.startsWith("video/"))modalContent.innerHTML='<video controls autoplay src="/uploads/'+filename+'"></video>';else modalContent.innerHTML="<p>Preview not available.</p>";modalOverlay.style.display="flex"}function closeViewer(){modalOverlay.style.display="none";modalContent.innerHTML=""}
async function uploadToFolder(){if(!currentFolderId)return showMsg("Open folder first","error");if(!uploadFiles.files.length)return showMsg("Select image/video","error");uploadBtn.disabled=true;uploadBtn.innerText="Uploading...";uploadProgressWrap.classList.remove("hide");uploadProgressBar.style.width="0%";uploadProgressBar.innerText="0%";let total=0;for(let f of uploadFiles.files)total+=f.size;uploadInfo.innerText="Selected size: "+(total/1048576).toFixed(2)+" MB";let fd=new FormData();for(let f of uploadFiles.files)fd.append("files",f);let x=new XMLHttpRequest();x.open("POST","/folder/"+currentFolderId+"/upload");x.setRequestHeader("Authorization",token);x.upload.onprogress=e=>{if(e.lengthComputable){let p=Math.round(e.loaded/e.total*100);uploadProgressBar.style.width=p+"%";uploadProgressBar.innerText=p+"%"}};x.onload=()=>{uploadBtn.disabled=false;uploadBtn.innerText="Upload Images / Videos";try{let d=JSON.parse(x.responseText);if(d.error)return showMsg(d.error,"error");showMsg("Files uploaded successfully");uploadFiles.value="";uploadInfo.innerText="";openFolder(currentFolderId);loadDashboard()}catch{showMsg("Upload failed","error")}};x.onerror=()=>{uploadBtn.disabled=false;uploadBtn.innerText="Upload Images / Videos";showMsg("Upload failed. Network issue.","error")};x.send(fd)}
async function deleteFolder(id){if(!confirm("Delete this folder?"))return;let r=await fetch("/folder/"+id+"/delete",{method:"DELETE",headers:{Authorization:token}}),d=await r.json();if(d.error)return showMsg(d.error,"error");showMsg("Folder deleted successfully");loadDashboard()}
async function loadMyFiles(){let r=await fetch("/my-files",{headers:{Authorization:token}}),d=await r.json();if(d.error)return showMsg(d.error,"error");renderFiles(d.files,"myfiles",allMyFiles)}
if(token)showPage("home");else showAuth("login");
</script></body></html>`));

app.post("/register",async(req,res)=>{let db=shape(readDB()),{name,password}=req.body,email=String(req.body.email||"").trim().toLowerCase();if(!name||!email||!password)return res.json({error:"All fields required"});if(!validGmail(email))return res.json({error:"Valid Gmail required. Example: name@gmail.com"});if(db.users.find(u=>u.email===email))return res.json({error:"Email already exists"});db.users.push({id:Date.now().toString(),name,email,password:await bcrypt.hash(password,10),authType:"local",createdAt:new Date().toISOString()});writeDB(db);res.json({message:"Register success"})});
app.post("/login",async(req,res)=>{let db=shape(readDB()),email=String(req.body.email||"").trim().toLowerCase();if(!validGmail(email))return res.json({error:"Valid Gmail required"});let u=db.users.find(x=>x.email===email);if(!u)return res.json({error:"User not found"});if(!u.password)return res.json({error:"This account uses Google login"});if(!await bcrypt.compare(req.body.password,u.password))return res.json({error:"Wrong password"});res.json({token:tokenFor(u)})});
app.post("/forgot/send-otp",async(req,res)=>{let db=shape(readDB()),email=String(req.body.email||"").trim().toLowerCase();if(!validGmail(email))return res.json({error:"Valid Gmail required"});let u=db.users.find(x=>x.email===email);if(!u)return res.json({error:"Email not registered"});if(!u.password)return res.json({error:"Google login account cannot reset password here"});let code=otp();db.otps=db.otps.filter(o=>o.email!==email);db.otps.push({email,otp:code,expiresAt:Date.now()+600000});writeDB(db);try{await sendOTP(email,code);res.json({message:"OTP sent"})}catch(e){console.log(e);res.json({error:"OTP email failed. Check EMAIL_USER and EMAIL_PASS"})}});
app.post("/forgot/reset",async(req,res)=>{let db=shape(readDB()),email=String(req.body.email||"").trim().toLowerCase(),{otp,newPassword}=req.body;if(!email||!otp||!newPassword)return res.json({error:"All fields required"});let rec=db.otps.find(o=>o.email===email&&o.otp===otp);if(!rec)return res.json({error:"Invalid OTP"});if(Date.now()>rec.expiresAt)return res.json({error:"OTP expired"});let u=db.users.find(x=>x.email===email);if(!u)return res.json({error:"User not found"});u.password=await bcrypt.hash(newPassword,10);db.otps=db.otps.filter(o=>o.email!==email);writeDB(db);res.json({message:"Password reset success"})});
app.get("/dashboard",auth,(req,res)=>{let db=shape(readDB()),u=db.users.find(x=>x.id===req.user.id);if(!u)return res.json({error:"User not found"});let used=storage(u.id),one=1024*1024*1024*1024;res.json({name:u.name,email:u.email,storageMB:mb(used),storagePercent:Math.min(used/one*100,100),folders:db.folders.filter(f=>f.user_id===u.id).map(f=>({id:f.id,name:f.name,filesCount:f.files.length}))})});
app.get("/settings",auth,(req,res)=>{let db=shape(readDB()),u=db.users.find(x=>x.id===req.user.id);if(!u)return res.json({error:"User not found"});res.json({name:u.name,email:u.email,storageMB:mb(storage(u.id))})});
app.get("/my-files",auth,(req,res)=>{let db=shape(readDB()),files=[];db.folders.filter(f=>f.user_id===req.user.id).forEach(folder=>folder.files.forEach(file=>files.push({...file,id:file.id,folderId:folder.id,sizeMB:mb(file.size)})));res.json({files})});
app.post("/folder/create",auth,async(req,res)=>{let db=shape(readDB()),{name,password}=req.body;if(!name||!password)return res.json({error:"Folder name and password required"});let u=db.users.find(x=>x.id===req.user.id);if(!u)return res.json({error:"User not found"});db.folders.push({id:Date.now().toString(),user_id:u.id,owner:u.name,name,password:await bcrypt.hash(password,10),files:[],unlockedUsers:[],createdAt:new Date().toISOString()});writeDB(db);res.json({message:"Folder created"})});
app.get("/search",auth,(req,res)=>{let db=shape(readDB()),q=(req.query.q||"").toLowerCase();res.json(db.folders.filter(f=>f.name.toLowerCase().includes(q)||f.owner.toLowerCase().includes(q)).map(f=>({id:f.id,name:f.name,owner:f.owner,filesCount:f.files.length,isOwner:f.user_id===req.user.id})))});
app.post("/folder/:id/unlock",auth,async(req,res)=>{let db=shape(readDB()),f=db.folders.find(x=>x.id===req.params.id);if(!f)return res.json({error:"Folder not found"});if(f.user_id===req.user.id)return res.json({message:"Owner access"});if(!await bcrypt.compare(req.body.password||"",f.password))return res.status(403).json({error:"Wrong folder password"});if(!f.unlockedUsers.includes(req.user.id))f.unlockedUsers.push(req.user.id);writeDB(db);res.json({message:"Folder unlocked"})});
app.get("/folder/:id",auth,(req,res)=>{let db=shape(readDB()),f=db.folders.find(x=>x.id===req.params.id);if(!f)return res.json({error:"Folder not found"});let own=f.user_id===req.user.id,un=f.unlockedUsers.includes(req.user.id);if(!own&&!un)return res.status(403).json({error:"Enter folder password first"});res.json({id:f.id,name:f.name,owner:f.owner,isOwner:own,files:f.files.map(file=>({id:file.id,originalname:file.originalname,filename:file.filename,type:file.type,sizeMB:mb(file.size)}))})});
app.post("/folder/:id/upload",auth,upload.array("files",100),(req,res)=>{let db=shape(readDB()),f=db.folders.find(x=>x.id===req.params.id);if(!f)return res.json({error:"Folder not found"});if(f.user_id!==req.user.id)return res.status(403).json({error:"Only owner can upload"});req.files.forEach(file=>f.files.push({id:Date.now().toString()+Math.random().toString(16).slice(2),originalname:file.originalname,filename:file.filename,type:file.mimetype,size:file.size,uploadedAt:new Date().toISOString()}));writeDB(db);res.json({message:"Files uploaded"})});
function access(db,folderId,fileId,uid){let folder=folderId==="myfiles"?db.folders.find(f=>f.user_id===uid&&f.files.some(x=>x.id===fileId)):db.folders.find(f=>f.id===folderId);if(!folder)return{error:"Folder not found"};let own=folder.user_id===uid,un=folder.unlockedUsers.includes(uid);if(!own&&!un)return{error:"Folder locked"};let file=folder.files.find(x=>x.id===fileId);if(!file)return{error:"File not found"};return{folder,file}}
app.get("/download/:folderId/:fileId",auth,(req,res)=>{let db=shape(readDB()),r=access(db,req.params.folderId,req.params.fileId,req.user.id);if(r.error)return res.status(403).send(r.error);let fp=path.join(__dirname,UPLOAD_DIR,r.file.filename);if(!fs.existsSync(fp))return res.status(404).send("Uploaded file missing");res.download(fp,r.file.originalname)});
app.delete("/folder/:id/delete",auth,(req,res)=>{let db=shape(readDB()),f=db.folders.find(x=>x.id===req.params.id);if(!f)return res.json({error:"Folder not found"});if(f.user_id!==req.user.id)return res.status(403).json({error:"Only owner can delete"});f.files.forEach(file=>{let p=path.join(__dirname,UPLOAD_DIR,file.filename);if(fs.existsSync(p))fs.unlinkSync(p)});db.folders=db.folders.filter(x=>x.id!==f.id);writeDB(db);res.json({message:"Folder deleted"})});
app.listen(PORT,()=>console.log("Website running: http://localhost:"+PORT));