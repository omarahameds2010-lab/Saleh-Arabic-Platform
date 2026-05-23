/**
 * Saleh Arabic Platform — Auth Core
 * Session Management | Device Fingerprinting | Security
 */

const Auth = (() => {

  // ─── Device Fingerprinting ───────────────────────────────────────
  const getDeviceFingerprint = () => {
    const components = [
      navigator.userAgent,
      navigator.language,
      screen.width + 'x' + screen.height,
      screen.colorDepth,
      new Date().getTimezoneOffset(),
      navigator.hardwareConcurrency || '',
      navigator.platform || '',
    ];
    // Simple hash
    const str = components.join('|');
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const c = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + c;
      hash |= 0;
    }
    return Math.abs(hash).toString(36);
  };

  // ─── Session ─────────────────────────────────────────────────────
  const SESSION_KEY = 'saleh_session';
  const DEVICE_KEY  = 'saleh_device_id';

  const getDeviceId = () => {
    let id = localStorage.getItem(DEVICE_KEY);
    if (!id) {
      id = getDeviceFingerprint() + '_' + Date.now().toString(36);
      localStorage.setItem(DEVICE_KEY, id);
    }
    return id;
  };

  const createSession = (user) => {
    const session = {
      user,
      deviceId: getDeviceId(),
      createdAt: Date.now(),
      expiresAt: Date.now() + (7 * 24 * 60 * 60 * 1000), // 7 days
      token: 'jwt_' + Math.random().toString(36).slice(2) + Date.now().toString(36),
    };
    localStorage.setItem(SESSION_KEY, JSON.stringify(session));
    return session;
  };

  const getSession = () => {
    try {
      const raw = localStorage.getItem(SESSION_KEY);
      if (!raw) return null;
      const session = JSON.parse(raw);
      if (Date.now() > session.expiresAt) {
        destroySession();
        return null;
      }
      // Device validation
      if (session.deviceId !== getDeviceId()) {
        destroySession();
        return null;
      }
      return session;
    } catch { return null; }
  };

  const destroySession = () => {
    localStorage.removeItem(SESSION_KEY);
  };

  const isLoggedIn = () => !!getSession();

  const getUser = () => {
    const s = getSession();
    return s ? s.user : null;
  };

  // ─── OTP System (client-side simulation) ─────────────────────────
  let _otpStore = {};

  const generateOTP = (identifier) => {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    _otpStore[identifier] = {
      code,
      expiresAt: Date.now() + 5 * 60 * 1000, // 5 min
      attempts: 0,
    };
    console.log(`[DEV] OTP for ${identifier}: ${code}`); // Remove in production
    return code;
  };

  const verifyOTP = (identifier, inputCode) => {
    const otp = _otpStore[identifier];
    if (!otp) return { ok: false, msg: 'لم يتم إرسال كود' };
    if (Date.now() > otp.expiresAt) {
      delete _otpStore[identifier];
      return { ok: false, msg: 'انتهت صلاحية الكود' };
    }
    otp.attempts++;
    if (otp.attempts > 5) return { ok: false, msg: 'تجاوزت عدد المحاولات' };
    if (otp.code !== inputCode.trim()) return { ok: false, msg: 'الكود غير صحيح' };
    delete _otpStore[identifier];
    return { ok: true };
  };

  // ─── Users Store (localStorage DB simulation) ─────────────────────
  const USERS_KEY = 'saleh_users';

  const getUsers = () => {
    try { return JSON.parse(localStorage.getItem(USERS_KEY)) || []; }
    catch { return []; }
  };

  const saveUsers = (users) => localStorage.setItem(USERS_KEY, JSON.stringify(users));

  const findUser = (identifier) => {
    const users = getUsers();
    return users.find(u =>
      u.email === identifier ||
      u.phone === identifier ||
      u.id    === identifier
    ) || null;
  };

  const registerUser = (data) => {
    const users = getUsers();
    if (users.find(u => u.email === data.email || u.phone === data.phone)) {
      return { ok: false, msg: 'الحساب موجود بالفعل' };
    }
    const user = {
      id:        'u_' + Date.now().toString(36),
      name:      data.name,
      email:     data.email,
      phone:     data.phone,
      password:  btoa(data.password), // Base64 simulation — use bcrypt in prod
      role:      'student',
      avatar:    data.name.charAt(0),
      xp:        0,
      level:     1,
      streak:    0,
      badges:    [],
      joinedAt:  Date.now(),
      verified:  true,
    };
    users.push(user);
    saveUsers(users);
    return { ok: true, user };
  };

  const loginUser = (identifier, password) => {
    const user = findUser(identifier);
    if (!user) return { ok: false, msg: 'الحساب غير موجود' };
    if (user.password !== btoa(password)) return { ok: false, msg: 'كلمة المرور غير صحيحة' };
    if (user.banned)  return { ok: false, msg: 'تم حظر هذا الحساب' };
    return { ok: true, user };
  };

  // Demo accounts seeding
  const seedDemoAccounts = () => {
    const users = getUsers();
    if (users.length > 0) return;
    const demos = [
      {
        id: 'admin_1', name: 'أستاذ صالح حسين', email: 'saleh@platform.com',
        phone: '01000000000', password: btoa('admin123'), role: 'admin',
        avatar: 'ص', xp: 0, level: 1, streak: 0, badges: [], joinedAt: Date.now(), verified: true,
      },
      {
        id: 'student_1', name: 'عمر أحمد', email: 'omar@student.com',
        phone: '01100000000', password: btoa('student123'), role: 'student',
        avatar: 'ع', xp: 4200, level: 7, streak: 14, badges: ['first_lesson','streak_7'],
        joinedAt: Date.now() - 30 * 86400000, verified: true,
      },
    ];
    saveUsers(demos);
  };

  // ─── Rate Limiting ────────────────────────────────────────────────
  const _attempts = {};

  const checkRateLimit = (key, max = 5, windowMs = 15 * 60 * 1000) => {
    const now = Date.now();
    if (!_attempts[key]) _attempts[key] = [];
    _attempts[key] = _attempts[key].filter(t => now - t < windowMs);
    if (_attempts[key].length >= max) {
      const wait = Math.ceil((windowMs - (now - _attempts[key][0])) / 1000 / 60);
      return { blocked: true, wait };
    }
    _attempts[key].push(now);
    return { blocked: false };
  };

  // ─── Guards ───────────────────────────────────────────────────────
  const requireAuth = (redirectTo = '../auth/login.html') => {
    if (!isLoggedIn()) {
      window.location.href = redirectTo;
      return false;
    }
    return true;
  };

  const requireRole = (role, redirectTo = '../auth/login.html') => {
    const user = getUser();
    if (!user || user.role !== role) {
      window.location.href = redirectTo;
      return false;
    }
    return true;
  };

  const redirectIfLoggedIn = (to = null) => {
    if (isLoggedIn()) {
      const user = getUser();
      const dest = to || (user.role === 'admin' ? '../admin/dashboard.html' : '../student/dashboard.html');
      window.location.href = dest;
      return true;
    }
    return false;
  };

  // ─── Init ─────────────────────────────────────────────────────────
  const init = () => {
    seedDemoAccounts();
    getDeviceId(); // ensure device id is set
  };

  return {
    init, getUser, getSession, createSession, destroySession,
    isLoggedIn, requireAuth, requireRole, redirectIfLoggedIn,
    generateOTP, verifyOTP,
    registerUser, loginUser, findUser,
    checkRateLimit, getDeviceId,
  };
})();

// Auto-init
Auth.init();
