const _originalFetch = window.fetch.bind(window);
window.fetch = function(url, opts = {}) {
  if (typeof url === 'string' && url.startsWith('/api/')) {
    const token = localStorage.getItem('vs_token');
    if (token) opts.headers = { ...(opts.headers || {}), 'Authorization': token };
  }
  return _originalFetch(url, opts);
};

const VS_AUTH = {
  logout: () => { localStorage.removeItem('vs_token'); location.reload(); },
  check: async () => {
    const token = localStorage.getItem('vs_token');
    if (!token) { VS_AUTH.showLoginForm(); return; }
    try {
      const r = await _originalFetch('/api/auth/me', { headers: { 'Authorization': token } });
      if (!r.ok) throw new Error();
      const user = await r.json();

      document.getElementById('sidebar-user-name').textContent = user.displayName;

      if (user.role === 'admin') document.getElementById('nav-system').style.display = 'block';

      document.getElementById('vs-app').style.display = 'block';
      if (typeof window.initAppAfterLogin === 'function') window.initAppAfterLogin(user);
    } catch { localStorage.removeItem('vs_token'); VS_AUTH.showLoginForm(); }
  },
  showLoginForm: () => {
    document.getElementById('vs-app').style.display = 'none';
    const overlay = document.createElement('div');
    overlay.innerHTML = `
      <div style="position:fixed;inset:0;background:#234A5B;display:flex;align-items:center;justify-content:center;z-index:99999;">
        <div style="background:#fff;padding:30px;border-radius:15px;width:90%;max-width:350px;text-align:center;">
          <h2 style="color:#234A5B;margin-bottom:20px;">VINSOUL ACADEMY</h2>
          <input id="vsl-u" type="text" placeholder="Tên đăng nhập" style="width:100%;padding:10px;margin-bottom:15px;border:1px solid #ccc;border-radius:8px;">
          <input id="vsl-p" type="password" placeholder="Mật khẩu" style="width:100%;padding:10px;margin-bottom:15px;border:1px solid #ccc;border-radius:8px;">
          <button onclick="VS_AUTH._doLogin()" style="width:100%;padding:12px;background:#F69922;color:#fff;border:none;border-radius:8px;font-weight:bold;cursor:pointer;">ĐĂNG NHẬP</button>
        </div>
      </div>`;
    document.body.appendChild(overlay);
  },
  _doLogin: async () => {
    const u = document.getElementById('vsl-u').value.trim();
    const p = document.getElementById('vsl-p').value;
    try {
      const res = await _originalFetch('/api/auth/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({username:u, password:p}) });
      if (!res.ok) return alert('Sai tên đăng nhập hoặc mật khẩu!');
      const data = await res.json();
      localStorage.setItem('vs_token', data.token); location.reload();
    } catch { alert('Lỗi kết nối Server Local'); }
  }
};
document.addEventListener('DOMContentLoaded', VS_AUTH.check);
