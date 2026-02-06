/* login.js - منطق تسجيل الدخول */
(function () {
  'use strict';

  function $(id) {
    return document.getElementById(id);
  }

  function setMessage(text) {
    const box = $('loginMessage');
    if (!box) return;
    if (!text) {
      box.style.display = 'none';
      box.textContent = '';
      return;
    }
    box.style.display = 'block';
    box.textContent = text;
  }

  function redirectAfterLogin() {
    const next = window.auth?.getNextFromQuery?.() || 'index.html';
    window.location.replace(next);
  }

  document.addEventListener('DOMContentLoaded', () => {
    $('year').textContent = new Date().getFullYear();

    if (!window.auth) {
      setMessage('تعذر تحميل نظام الدخول (auth.js).');
      return;
    }

    const loginForm = $('loginForm');
    const loginBtn = loginForm?.querySelector('button[type="submit"]');
    const changeForm = $('changePasswordForm');
    const changeBtn = changeForm?.querySelector('button[type="submit"]');

    const setBusy = (busy, text) => {
      if (loginBtn) loginBtn.disabled = !!busy;
      if (changeBtn) changeBtn.disabled = !!busy;
      if (busy) setMessage(text || 'جاري التحميل...');
    };

    (async () => {
      // ملاحظة: لم نعد ننشئ بيانات افتراضية نهائياً
      window.auth.ensureDefaultUser();

      // إذا مسجل دخول مسبقاً، نروح مباشرة
      if (window.auth.isLoggedIn()) {
        redirectAfterLogin();
        return;
      }

      // مزامنة المستخدمين من السحابة إن توفرت
      setBusy(true, 'جاري مزامنة المستخدمين...');
      try {
        if (typeof window.auth.ready === 'function') {
          await window.auth.ready();
        }
      } catch (_) {
        // تجاهل: نكمل بالوضع المحلي
      } finally {
        setBusy(false, '');
        setMessage('');
      }

      const hasUsers = typeof window.auth.hasUsers === 'function'
        ? window.auth.hasUsers()
        : (window.auth.getUsers().length > 0);

      if (!hasUsers) {
        setMessage('لا يوجد مستخدمين مضبوطين (محلياً أو بالسحابة). يرجى إعداد مستخدم على جهاز واحد أولاً.');
      }

      $('loginUsername')?.focus();

      loginForm?.addEventListener('submit', async (e) => {
        e.preventDefault();
        setMessage('');

        const hasUsersNow = typeof window.auth.hasUsers === 'function'
          ? window.auth.hasUsers()
          : (window.auth.getUsers().length > 0);
        if (!hasUsersNow) {
          setMessage('لا يمكن تسجيل الدخول لأنه لا يوجد مستخدمين مضبوطين.');
          return;
        }

        const username = $('loginUsername')?.value || '';
        const password = $('loginPassword')?.value || '';
        const remember = !!$('rememberMe')?.checked;

        setBusy(true, 'جاري تسجيل الدخول...');
        try {
          const result = await window.auth.login({ username, password, remember });
          if (!result.ok) {
            setMessage(result.error || 'حدث خطأ.');
            return;
          }
          redirectAfterLogin();
        } finally {
          setBusy(false, '');
        }
      });

      changeForm?.addEventListener('submit', async (e) => {
        e.preventDefault();
        setMessage('');

        const username = $('cpUsername')?.value || '';
        const oldPassword = $('cpOld')?.value || '';
        const newPassword = $('cpNew')?.value || '';

        setBusy(true, 'جاري تغيير كلمة المرور...');
        try {
          const result = await window.auth.changePassword({ username, oldPassword, newPassword });
          if (!result.ok) {
            setMessage(result.error || 'تعذر تغيير كلمة المرور.');
            return;
          }

          setMessage('تم تغيير كلمة المرور بنجاح. يمكنك تسجيل الدخول الآن.');
          $('loginUsername').value = username;
          $('loginPassword').value = '';
          $('loginPassword')?.focus();
        } finally {
          setBusy(false, '');
        }
      });
    })();
  });
})();

