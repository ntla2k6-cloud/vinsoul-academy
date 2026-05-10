// ═══════════════════════════════════════════════════════════════
//  server.js – Vinsoul Academy v2.0
//  Nâng cấp: RBAC 4 cấp, Audit Log, VietQR, Zalo webhook stub,
//            tính ngày kết thúc tự động, nhắc học phí
// ═══════════════════════════════════════════════════════════════
require('module').globalPaths.push('/home/zijgohrz/nodevenv/app/18/lib/node_modules');
const express = require('express');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');
const jwt     = require('jsonwebtoken');
const bcrypt  = require('bcryptjs');

const app    = express();
const PORT   = process.env.PORT || 3000;
const DB     = path.join(__dirname, 'database.json');
const USERS  = path.join(__dirname, 'users.json');
const AUDIT  = path.join(__dirname, 'audit.json');
const SECRET = 'vinsoul_secret_key_2025';

// ── Bank info VietQR ──
const BANK = {
  bin:     '970436', // Vietcombank BIN
  account: '1731238888',
  name:    'HKD VINSOUL'
};

// ── Ngày nghỉ lễ cố định (MM-DD) ──
const HOLIDAYS = [
  '01-01','04-30','05-01','09-02','09-03',
  '12-25','01-27','01-28','01-29','01-30','01-31' // Tết âm lịch ~ cố định tháng 1-2
];
// Danh sách ngày nghỉ Tết âm lịch theo năm (YYYY-MM-DD) cập nhật thêm tại đây
const LUNAR_NEW_YEAR = {
  '2024': ['2024-02-08','2024-02-09','2024-02-10','2024-02-11','2024-02-12','2024-02-13','2024-02-14'],
  '2025': ['2025-01-27','2025-01-28','2025-01-29','2025-01-30','2025-01-31','2025-02-01','2025-02-02'],
  '2026': ['2026-02-15','2026-02-16','2026-02-17','2026-02-18','2026-02-19','2026-02-20','2026-02-21'],
};

app.use(cors());
app.use(express.json({ limit: '20mb' }));

// Chặn truy cập file nhạy cảm
['server.js','users.json','database.json','audit.json'].forEach(f => {
  app.get('/' + f, (_, res) => res.status(403).end());
});

// ── DB helpers ──
const EMPTY = {
  students:[], staff:[], leads:[], classes:[], attendance:[],
  makeups:[], templates:[], customCourses:[], customPrices:{},
  notifications:[], zaloCfg:{}
};

function loadDB() {
  try { return { ...EMPTY, ...JSON.parse(fs.readFileSync(DB,'utf8')) }; }
  catch { return {...EMPTY}; }
}
function saveDB(d) {
  fs.writeFileSync(DB + '.tmp', JSON.stringify(d,null,2));
  fs.renameSync(DB + '.tmp', DB);
}

// ── Users ──
function loadUsers() {
  if (!fs.existsSync(USERS)) {
    const def = [{
      id:1, username:'admin',
      passwordHash: bcrypt.hashSync('Vinsoul@2024',10),
      displayName:'Quan Tri Vien', role:'admin'
    }];
    fs.writeFileSync(USERS, JSON.stringify(def,null,2));
    return def;
  }
  try { return JSON.parse(fs.readFileSync(USERS,'utf8')); }
  catch { return []; }
}
function saveUsers(u) { fs.writeFileSync(USERS, JSON.stringify(u,null,2)); }

// ── Audit Log ──
function loadAudit() {
  try { return JSON.parse(fs.readFileSync(AUDIT,'utf8')); }
  catch { return []; }
}
function writeAudit(user, action, detail) {
  try {
    const logs = loadAudit();
    logs.unshift({
      id: Date.now(),
      user: user || 'system',
      action,
      detail: typeof detail === 'object' ? JSON.stringify(detail) : String(detail||''),
      time: new Date().toISOString()
    });
    // Giữ tối đa 2000 dòng
    if (logs.length > 2000) logs.splice(2000);
    fs.writeFileSync(AUDIT, JSON.stringify(logs,null,2));
  } catch(e) { console.error('Audit write error:', e.message); }
}

// ── Rate limit ──
const tries = new Map();
function locked(ip) {
  const r = tries.get(ip); if (!r) return false;
  if (Date.now() > r.reset) { tries.delete(ip); return false; }
  return r.n >= 5;
}
function fail(ip) {
  const r = tries.get(ip) || { n:0, reset: Date.now()+900000 };
  if (Date.now() > r.reset) { r.n=0; r.reset=Date.now()+900000; }
  r.n++; tries.set(ip,r);
}

// ── Auth middleware ──
function auth(req, res, next) {
  const h = req.headers['authorization'] || '';
  const t = h.startsWith('Bearer ') ? h.slice(7) : h;
  if (!t) return res.status(401).json({ error:'Chua dang nhap' });
  try { req.user = jwt.verify(t, SECRET); next(); }
  catch { res.status(401).json({ error:'Phien dang nhap het han' }); }
}
function admin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error:'Chi quan tri vien moi co quyen nay' });
  next();
}
function staffOrAdmin(req, res, next) {
  if (!['admin','staff'].includes(req.user.role)) return res.status(403).json({ error:'Khong co quyen' });
  next();
}

// ══════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════
app.post('/api/auth/login', (req, res) => {
  const ip = req.ip || '';
  if (locked(ip)) return res.status(429).json({ error:'Tam khoa do dang nhap sai nhieu lan.' });
  const { username='', password='' } = req.body || {};
  if (!username || !password) return res.status(400).json({ error:'Vui long nhap ten dang nhap va mat khau' });
  const users = loadUsers();
  const user  = users.find(u => u.username === username.trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    fail(ip);
    const r = tries.get(ip);
    return res.status(401).json({ error:`Sai ten dang nhap hoac mat khau. Con ${Math.max(0,5-(r?r.n:1))} lan thu.` });
  }
  tries.delete(ip);
  writeAudit(user.username, 'LOGIN', 'Dang nhap thanh cong');
  const token = jwt.sign(
    { id:user.id, username:user.username, displayName:user.displayName, role:user.role },
    SECRET, { expiresIn:'8h' }
  );
  res.json({ token, username:user.username, displayName:user.displayName, role:user.role });
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ username:req.user.username, displayName:req.user.displayName, role:req.user.role });
});

app.post('/api/auth/change-password', auth, (req, res) => {
  const { currentPassword='', newPassword='' } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error:'Vui long nhap day du thong tin' });
  if (newPassword.length < 8) return res.status(400).json({ error:'Mat khau moi phai co it nhat 8 ky tu' });
  const users = loadUsers();
  const i = users.findIndex(u => u.id === req.user.id);
  if (i === -1) return res.status(404).json({ error:'Khong tim thay tai khoan' });
  if (!bcrypt.compareSync(currentPassword, users[i].passwordHash)) return res.status(401).json({ error:'Mat khau hien tai khong dung' });
  users[i].passwordHash = bcrypt.hashSync(newPassword, 10);
  saveUsers(users);
  writeAudit(req.user.username, 'CHANGE_PASSWORD', 'Doi mat khau thanh cong');
  res.json({ ok:true });
});

// ══════════════════════════════════════════
// USER MANAGEMENT (Admin only)
// ══════════════════════════════════════════
app.get('/api/users', auth, admin, (req, res) => {
  res.json(loadUsers().map(u => ({ id:u.id, username:u.username, displayName:u.displayName, role:u.role })));
});

app.post('/api/users', auth, admin, (req, res) => {
  const { username='', password='', displayName='', role='' } = req.body || {};
  if (!username||!password||!displayName||!role) return res.status(400).json({ error:'Vui long nhap day du thong tin' });
  if (!['admin','staff','teacher','student'].includes(role)) return res.status(400).json({ error:'Phan quyen khong hop le' });
  if (password.length < 8) return res.status(400).json({ error:'Mat khau phai co it nhat 8 ky tu' });
  const users = loadUsers();
  if (users.find(u => u.username === username.trim().toLowerCase())) return res.status(409).json({ error:'Ten dang nhap da ton tai' });
  const extra = {};
  if (role === 'teacher' && req.body.linkedStaffId) extra.linkedStaffId = req.body.linkedStaffId;
  if (role === 'student' && req.body.linkedStudentId) extra.linkedStudentId = req.body.linkedStudentId;
  const u = {
    id: Date.now(),
    username: username.trim().toLowerCase(),
    passwordHash: bcrypt.hashSync(password,10),
    displayName: displayName.trim(),
    role,
    ...extra
  };
  users.push(u); saveUsers(users);
  writeAudit(req.user.username, 'CREATE_USER', `Tao tai khoan: ${u.username} (${role})`);
  res.json({ ok:true, id:u.id });
});

app.put('/api/users/:id', auth, admin, (req, res) => {
  const id = Number(req.params.id);
  const { displayName, role, password, linkedStaffId, linkedStudentId } = req.body || {};
  const users = loadUsers();
  const i = users.findIndex(u => u.id === id);
  if (i === -1) return res.status(404).json({ error:'Khong tim thay tai khoan' });
  if (users[i].id === req.user.id && role && role !== 'admin') return res.status(400).json({ error:'Khong the ha cap quyen cua chinh minh' });
  if (displayName) users[i].displayName = displayName.trim();
  if (role && ['admin','staff','teacher','student'].includes(role)) users[i].role = role;
  if (linkedStaffId !== undefined) users[i].linkedStaffId = linkedStaffId;
  if (linkedStudentId !== undefined) users[i].linkedStudentId = linkedStudentId;
  if (password) {
    if (password.length < 8) return res.status(400).json({ error:'Mat khau phai co it nhat 8 ky tu' });
    users[i].passwordHash = bcrypt.hashSync(password, 10);
  }
  saveUsers(users);
  writeAudit(req.user.username, 'UPDATE_USER', `Cap nhat tai khoan ID: ${id}`);
  res.json({ ok:true });
});

app.delete('/api/users/:id', auth, admin, (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error:'Khong the xoa tai khoan cua chinh minh' });
  const users = loadUsers();
  const i = users.findIndex(u => u.id === id);
  if (i === -1) return res.status(404).json({ error:'Khong tim thay tai khoan' });
  if (users[i].role === 'admin' && users.filter((_,j)=>j!==i&&_.role==='admin').length === 0)
    return res.status(400).json({ error:'Phai con it nhat 1 quan tri vien' });
  const uname = users[i].username;
  users.splice(i,1); saveUsers(users);
  writeAudit(req.user.username, 'DELETE_USER', `Xoa tai khoan: ${uname}`);
  res.json({ ok:true });
});

// ══════════════════════════════════════════
// DATA LOAD / SAVE
// ══════════════════════════════════════════
app.get('/api/load', auth, (req, res) => {
  const db = loadDB();
  const role = req.user.role;

  // Student: chỉ trả về dữ liệu của chính mình
  if (role === 'student') {
    const users = loadUsers();
    const u = users.find(x => x.id === req.user.id);
    const sid = u && u.linkedStudentId;
    const myStudent = sid ? (db.students||[]).filter(s => String(s.id) === String(sid)) : [];
    return res.json({
      students: myStudent,
      courses: [],
      attendance: (db.attendance||[]).filter(a => {
        return myStudent.some(ms => a.records && a.records[String(ms.id)]);
      }),
      makeups: (db.makeups||[]).filter(m => myStudent.some(ms => String(m.studentId) === String(ms.id)))
    });
  }

  // Teacher: chỉ trả về học viên trong lớp mình dạy
  if (role === 'teacher') {
    const users = loadUsers();
    const u = users.find(x => x.id === req.user.id);
    const staffId = u && u.linkedStaffId;
    const staffMember = staffId ? (db.staff||[]).find(s => String(s.id) === String(staffId)) : null;
    const teacherName = staffMember ? staffMember.name : req.user.displayName;
    const myClasses = (db.classes||[]).filter(c =>
      c.teacher && c.teacher.includes(teacherName)
    );
    const myClassIds = myClasses.map(c => String(c.id));
    const myStudents = (db.students||[]).filter(s => myClassIds.includes(String(s.classid)));
    return res.json({
      ...db,
      students: myStudents,
      classes: myClasses,
      staff: db.staff
    });
  }

  res.json(db);
});

app.post('/api/save', auth, (req, res) => {
  try {
    const db = loadDB();
    const role = req.user.role;

    // Student: chỉ được lưu trường share (chia sẻ của học viên)
    if (role === 'student') {
      const users = loadUsers();
      const u = users.find(x => x.id === req.user.id);
      const sid = u && u.linkedStudentId;
      if (sid && req.body.studentShare !== undefined) {
        const idx = (db.students||[]).findIndex(s => String(s.id) === String(sid));
        if (idx !== -1) {
          db.students[idx].studentShare = req.body.studentShare;
          saveDB(db);
          writeAudit(req.user.username, 'STUDENT_SHARE', `HV ${sid} cap nhat chia se`);
          return res.json({ ok:true });
        }
      }
      return res.status(403).json({ error:'Khong co quyen luu' });
    }

    // Teacher: chỉ được ghi vào fields nhận xét, báo bài, video
    if (role === 'teacher') {
      if (req.body.studentFeedback) {
        const { studentId, feedback, homework, mediaUrls } = req.body.studentFeedback;
        const idx = (db.students||[]).findIndex(s => String(s.id) === String(studentId));
        if (idx !== -1) {
          if (!db.students[idx].feedbacks) db.students[idx].feedbacks = [];
          db.students[idx].feedbacks.push({
            by: req.user.displayName, at: new Date().toISOString(), feedback, homework, mediaUrls
          });
          saveDB(db);
          writeAudit(req.user.username, 'TEACHER_FEEDBACK', `GV nhan xet HV ${studentId}`);
          return res.json({ ok:true });
        }
      }
      // Teacher có thể lưu điểm danh
      if (req.body.attendance !== undefined) {
        db.attendance = req.body.attendance;
        saveDB(db);
        writeAudit(req.user.username, 'SAVE_ATTENDANCE', 'GV luu diem danh');
        return res.json({ ok:true });
      }
      return res.status(403).json({ error:'Giao vien khong co quyen luu du lieu nay' });
    }

    // Staff/Admin: lưu tất cả
    const oldDB = JSON.stringify(db);
    Object.keys(EMPTY).forEach(k => { if (req.body[k] !== undefined) db[k] = req.body[k]; });
    saveDB(db);

    // Audit: phát hiện thay đổi
    if (req.body.students) writeAudit(req.user.username, 'SAVE_STUDENTS', `Luu ${(req.body.students||[]).length} hoc vien`);
    if (req.body.staff) writeAudit(req.user.username, 'SAVE_STAFF', `Luu ${(req.body.staff||[]).length} nhan su`);
    if (req.body.leads) writeAudit(req.user.username, 'SAVE_LEADS', `Luu ${(req.body.leads||[]).length} lead`);

    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

// ══════════════════════════════════════════
// AUDIT LOG (Admin only)
// ══════════════════════════════════════════
app.get('/api/audit', auth, admin, (req, res) => {
  const logs = loadAudit();
  const limit = Math.min(Number(req.query.limit)||200, 500);
  res.json(logs.slice(0, limit));
});

// ══════════════════════════════════════════
// TÍNH NGÀY KẾT THÚC TỰ ĐỘNG
// Input: { startDate: 'YYYY-MM-DD', totalSessions: N, sessionsPerWeek: N }
// Output: { endDate: 'YYYY-MM-DD' }
// ══════════════════════════════════════════
app.post('/api/calc-end-date', auth, (req, res) => {
  const { startDate, totalSessions, sessionsPerWeek=2 } = req.body || {};
  if (!startDate || !totalSessions) return res.status(400).json({ error:'Thieu thong tin' });

  const allHolidays = new Set();
  // Thêm ngày lễ cố định (tất cả năm)
  const yr = new Date(startDate).getFullYear();
  for (let y = yr; y <= yr + 2; y++) {
    HOLIDAYS.forEach(md => allHolidays.add(`${y}-${md}`));
    if (LUNAR_NEW_YEAR[String(y)]) {
      LUNAR_NEW_YEAR[String(y)].forEach(d => allHolidays.add(d));
    }
  }

  let date = new Date(startDate + 'T00:00:00');
  let sessions = 0;
  const maxIter = 1000;
  let iter = 0;
  while (sessions < totalSessions && iter < maxIter) {
    iter++;
    const dow = date.getDay(); // 0=CN
    const dateStr = date.toISOString().slice(0,10);
    // Bỏ qua Chủ Nhật và ngày lễ
    if (dow !== 0 && !allHolidays.has(dateStr)) {
      sessions++;
    }
    if (sessions < totalSessions) date.setDate(date.getDate() + 1);
  }
  res.json({ endDate: date.toISOString().slice(0,10) });
});

// ══════════════════════════════════════════
// VIETQR GENERATION
// ══════════════════════════════════════════
app.post('/api/vietqr', auth, (req, res) => {
  const { amount, studentCode, note } = req.body || {};
  if (!amount) return res.status(400).json({ error:'Thieu so tien' });
  const addInfo = note || `VS_${studentCode||'HV'}_HOCPHI`;
  // VietQR URL format: https://img.vietqr.io/image/{bank}-{account}-{template}.jpg?amount={amount}&addInfo={note}&accountName={name}
  const qrUrl = `https://img.vietqr.io/image/${BANK.bin}-${BANK.account}-compact2.jpg` +
    `?amount=${encodeURIComponent(amount)}&addInfo=${encodeURIComponent(addInfo)}&accountName=${encodeURIComponent(BANK.name)}`;
  res.json({
    qrUrl,
    bank: BANK,
    amount,
    addInfo
  });
});

// ══════════════════════════════════════════
// NOTIFICATIONS
// ══════════════════════════════════════════
app.get('/api/notifications', auth, staffOrAdmin, (req, res) => {
  const db = loadDB();
  res.json((db.notifications||[]).slice(0,50));
});

app.post('/api/notifications/read', auth, staffOrAdmin, (req, res) => {
  const db = loadDB();
  const { id } = req.body || {};
  if (id) {
    const idx = (db.notifications||[]).findIndex(n => n.id === id);
    if (idx !== -1) db.notifications[idx].read = true;
  } else {
    (db.notifications||[]).forEach(n => n.read = true);
  }
  saveDB(db);
  res.json({ ok:true });
});

// ══════════════════════════════════════════
// ZALO WEBHOOK STUB
// (Kết nối thật cần OA_ACCESS_TOKEN từ Zalo Business)
// ══════════════════════════════════════════
app.get('/api/zalo/config', auth, admin, (req, res) => {
  const db = loadDB();
  res.json(db.zaloCfg || {});
});

app.post('/api/zalo/config', auth, admin, (req, res) => {
  const db = loadDB();
  const { oaAccessToken, templateId } = req.body || {};
  db.zaloCfg = { oaAccessToken, templateId, updatedAt: new Date().toISOString() };
  saveDB(db);
  writeAudit(req.user.username, 'ZALO_CONFIG', 'Cap nhat cau hinh Zalo ZNS');
  res.json({ ok:true });
});

// Gửi ZNS thật (chỉ chạy nếu có OA token)
app.post('/api/zalo/send', auth, staffOrAdmin, async (req, res) => {
  const db = loadDB();
  const { phone, templateData } = req.body || {};
  const cfg = db.zaloCfg || {};
  if (!cfg.oaAccessToken) return res.status(400).json({ error:'Chua cau hinh Zalo OA token. Vao Cai Dat -> Zalo ZNS de nhap.' });
  // Gọi Zalo ZNS API
  try {
    const resp = await fetch('https://business.openapi.zalo.me/message/template', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'access_token': cfg.oaAccessToken
      },
      body: JSON.stringify({
        phone,
        template_id: cfg.templateId,
        template_data: templateData
      })
    });
    const data = await resp.json();
    if (data.error !== 0) return res.status(400).json({ error: data.message || 'Loi Zalo ZNS', zaloError: data });
    writeAudit(req.user.username, 'ZALO_SEND', `Gui ZNS toi ${phone}`);
    res.json({ ok:true, zalo: data });
  } catch(e) {
    res.status(500).json({ error:'Loi ket noi Zalo: ' + e.message });
  }
});

// ══════════════════════════════════════════
// TEACHER FEEDBACK (riêng)
// ══════════════════════════════════════════
app.post('/api/student/:id/feedback', auth, (req, res) => {
  if (!['admin','staff','teacher'].includes(req.user.role))
    return res.status(403).json({ error:'Khong co quyen' });
  const db = loadDB();
  const idx = (db.students||[]).findIndex(s => String(s.id) === String(req.params.id));
  if (idx === -1) return res.status(404).json({ error:'Khong tim thay hoc vien' });
  if (!db.students[idx].feedbacks) db.students[idx].feedbacks = [];
  const entry = {
    id: Date.now(),
    by: req.user.displayName,
    byRole: req.user.role,
    at: new Date().toISOString(),
    feedback: req.body.feedback || '',
    homework: req.body.homework || '',
    mediaUrls: req.body.mediaUrls || []
  };
  db.students[idx].feedbacks.push(entry);
  saveDB(db);
  writeAudit(req.user.username, 'ADD_FEEDBACK', `HV ${req.params.id}: ${(req.body.feedback||'').slice(0,40)}`);
  res.json({ ok:true, entry });
});

app.post('/api/student/:id/share', auth, (req, res) => {
  const db = loadDB();
  const users = loadUsers();
  const u = users.find(x => x.id === req.user.id);
  const sid = req.params.id;
  // Student chỉ tự sửa của mình
  if (req.user.role === 'student' && (!u || String(u.linkedStudentId) !== String(sid)))
    return res.status(403).json({ error:'Khong co quyen' });
  const idx = (db.students||[]).findIndex(s => String(s.id) === String(sid));
  if (idx === -1) return res.status(404).json({ error:'Khong tim thay' });
  db.students[idx].studentShare = req.body.share || '';
  saveDB(db);
  res.json({ ok:true });
});

// ══════════════════════════════════════════
// BACKUP / RESTORE / EXPORT (giữ nguyên)
// ══════════════════════════════════════════
app.get('/api/backup', auth, (req, res) => {
  const fn = `vinsoul_backup_${new Date().toISOString().slice(0,10)}.json`;
  res.setHeader('Content-Disposition', `attachment; filename="${fn}"`);
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.send(JSON.stringify(loadDB(), null, 2));
});

app.post('/api/restore', auth, (req, res) => {
  try {
    if (typeof req.body !== 'object' || Array.isArray(req.body)) return res.status(400).json({ error:'Du lieu khong hop le' });
    saveDB({ ...EMPTY, ...req.body });
    writeAudit(req.user.username, 'RESTORE', 'Khoi phuc du lieu tu file');
    res.json({ ok:true });
  } catch(e) { res.status(500).json({ error:e.message }); }
});

app.get('/api/export/:type', auth, (req, res) => {
  const { type } = req.params;
  const db = loadDB();
  const BOM = '\uFEFF';
  const fd = d => d ? new Date(d).toLocaleDateString('vi-VN') : '';
  const fn = n => Number(n||0).toLocaleString('vi-VN');
  const q  = v => `"${String(v||'').replace(/"/g,'""')}"`;
  let csv = BOM, filename = '';
  if (type === 'students') {
    filename = 'HocVien.csv';
    csv += ['#','Ho Ten','Ngay Sinh','Phu Huynh','SDT','Mon Hoc','Goi Lop','Ngay BD','Ngay KT','Hinh Thuc','So Tien','Ngay Nop','Ghi Chu'].map(q).join(',') + '\n';
    (db.students||[]).forEach((s,i) => { csv += [i+1,s.name,fd(s.dob),s.parent,s.phone,s.subject,s.pkg||'',fd(s.start),fd(s.end),s.payment,fn(s.amount),fd(s.paydate),s.note||''].map(q).join(',') + '\n'; });
  } else if (type === 'staff') {
    filename = 'NhanSu.csv';
    csv += ['#','Ho Ten','Ngay Sinh','SDT','Vi Tri','Tinh Trang','Ghi Chu'].map(q).join(',') + '\n';
    (db.staff||[]).forEach((s,i) => { csv += [i+1,s.name,fd(s.dob),s.phone,s.role,s.status,s.note||''].map(q).join(',') + '\n'; });
  } else if (type === 'leads') {
    filename = 'HVTiemNang.csv';
    csv += ['#','Ho Ten','Ngay Sinh','Phu Huynh','SDT','Khoa Hoc','Nguon','Tinh Trang','Ghi Chu'].map(q).join(',') + '\n';
    (db.leads||[]).forEach((l,i) => { csv += [i+1,l.name,fd(l.dob),l.parent,l.phone,l.course,l.source,l.status,l.note||''].map(q).join(',') + '\n'; });
  } else if (type === 'revenue') {
    filename = 'DoanhThu.csv';
    csv += ['#','Ho Ten','Mon Hoc','Goi Lop','Hinh Thuc','So Tien','Ngay Nop'].map(q).join(',') + '\n';
    const paid = (db.students||[]).filter(s => s.payment !== 'Chua Thanh Toan' && s.amount);
    paid.forEach((s,i) => { csv += [i+1,s.name,s.subject,s.pkg||'',s.payment,fn(s.amount),fd(s.paydate)].map(q).join(',') + '\n'; });
    const total = paid.reduce((a,s) => a+Number(s.amount||0), 0);
    csv += `"","","","","TONG",${q(fn(total))},""\n`;
  } else if (type === 'attendance') {
    filename = 'ChamCong.csv';
    csv += ['Ngay','Lop','HV','Trang Thai'].map(q).join(',') + '\n';
    (db.attendance||[]).forEach(a => {
      const cls = (db.classes||[]).find(c => String(c.id) === String(a.classId));
      Object.entries(a.records||{}).forEach(([sid, status]) => {
        const st = (db.students||[]).find(s => String(s.id) === String(sid));
        csv += [fd(a.date), cls?cls.name:'?', st?st.name:sid, status].map(q).join(',') + '\n';
      });
    });
  } else return res.status(404).json({ error:'Loai khong hop le' });
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(filename)}`);
  res.send(csv);
});

// ══════════════════════════════════════════
// TUITION REMINDER CHECK (cron-style, gọi thủ công hoặc tự động)
// ══════════════════════════════════════════
app.post('/api/check-reminders', auth, staffOrAdmin, (req, res) => {
  const db = loadDB();
  const today = new Date();
  const newNotifs = [];

  (db.students||[]).forEach(s => {
    if (!s.end || s.payment !== 'Chua Thanh Toan') return;
    const daysLeft = Math.ceil((new Date(s.end) - today) / (1000*60*60*24));
    if (daysLeft >= 0 && daysLeft <= 14) {
      const already = (db.notifications||[]).find(n =>
        n.type === 'TUITION_REMINDER' && n.studentId === s.id &&
        n.createdDate === today.toISOString().slice(0,10)
      );
      if (!already) {
        newNotifs.push({
          id: Date.now() + Math.random(),
          type: 'TUITION_REMINDER',
          studentId: s.id,
          studentName: s.name,
          daysLeft,
          endDate: s.end,
          read: false,
          createdDate: today.toISOString().slice(0,10),
          createdAt: today.toISOString(),
          message: `${s.name} con ${daysLeft} ngay ket thuc khoa (${s.subject}). Chua dong hoc phi.`
        });
      }
    }
  });

  if (newNotifs.length) {
    if (!db.notifications) db.notifications = [];
    db.notifications = [...newNotifs, ...db.notifications].slice(0,500);
    saveDB(db);
  }
  res.json({ newCount: newNotifs.length, notifications: newNotifs });
});

// ══════════════════════════════════════════
// STATIC FILES
// ══════════════════════════════════════════
app.use(express.static('/home/zijgohrz/app'));
app.get('/index.html', (req, res) => res.sendFile('/home/zijgohrz/app/index.html'));
app.get('/', (req, res) => res.sendFile('/home/zijgohrz/app/index.html'));

app.use(function(req, res) {
  const indexPath = '/home/zijgohrz/app/index.html';
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send('Khong tim thay trang');
  }
});

app.use(function(err, req, res, next) {
  console.error('[LOI]', err.stack || err.message);
  if (req.path.startsWith('/api/')) return res.status(500).json({ error: err.message });
  res.status(500).send('Loi server: ' + err.message);
});

app.listen(PORT, function() {
  loadUsers();
  console.log('Vinsoul Academy v2.0 dang chay tai port: ' + PORT);
});

process.on('uncaughtException', function(err) {
  console.error('[LOI NGHIEM TRONG]', err.message);
});
process.on('unhandledRejection', function(reason) {
  console.error('[LOI PROMISE]', reason);
});
