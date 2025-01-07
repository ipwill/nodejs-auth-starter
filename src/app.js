// src/app.js
import axios from 'axios';
import { showModal, toggleSpinner, validatePassword } from '../public/js/script.js';

const authStorage = {
  store(token, username) {
    localStorage.setItem('authToken', token);
    localStorage.setItem('username', username);
  },
  clear() {
    localStorage.removeItem('authToken');
    localStorage.removeItem('username');
    localStorage.removeItem('tempUsername');
  },
  get() {
    return {
      token: localStorage.getItem('authToken'),
      username: localStorage.getItem('username'),
    };
  },
  getTempUsername() {
    return localStorage.getItem('tempUsername');
  },
  setTempUsername(username) {
    localStorage.setItem('tempUsername', username);
  },
};

const formManager = {
  hideAll() {
    document.querySelectorAll('.form-section').forEach(form => form.classList.remove('active'));
  },
  show(formId) {
    this.hideAll();
    const form = document.getElementById(formId);
    if (form) {
      form.classList.add('active');
    }
  },
  show2FA(method) {
    this.show('2fa-form');
    const totp = document.getElementById('totp-container');
    const email = document.getElementById('email-container');
    if (method === 'totp') {
      totp.classList.remove('hidden');
      email.classList.add('hidden');
    } else {
      totp.classList.add('hidden');
      email.classList.remove('hidden');
    }
  },
};

const api = axios.create({
  baseURL: '/api/',
});

const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

api.defaults.headers.post['X-CSRF-Token'] = csrfToken;
api.defaults.headers.put['X-CSRF-Token'] = csrfToken;
api.defaults.headers.delete['X-CSRF-Token'] = csrfToken;

const handlers = {
  async registerHandler(event) {
    event.preventDefault();
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value.trim();
    const twoFactorMethod = document.getElementById('2fa-method').value;
    const bypass2FA = document.getElementById('bypass-2fa-register').checked;
    const errorElement = document.getElementById('register-error');
    errorElement.textContent = '';

    if (!username || !email || !password) {
      errorElement.textContent = 'Please fill in all fields.';
      return;
    }
    if (!validatePassword(password)) {
      errorElement.textContent = 'Password does not meet the requirements.';
      return;
    }

    try {
      toggleSpinner(true, 'register-button');
      const response = await api.post('register', { username, email, password, twoFactorMethod, bypass2FA });
      if (response.status === 201) {
        authStorage.store(response.data.token, username);
        if (!bypass2FA && response.data.twoFactorMethod) {
          authStorage.setTempUsername(username);
          formManager.show2FA(response.data.twoFactorMethod);
          if (response.data.twoFactorMethod === 'totp' && response.data.qrCode) {
            const qrCodeImage = document.getElementById('qr-code');
            if (qrCodeImage) {
              qrCodeImage.src = response.data.qrCode;
              qrCodeImage.classList.remove('hidden');
            }
          }
        } else {
          window.location.href = `/user/${response.data.dashboardToken}`;
        }
      }
    } catch (err) {
      errorElement.textContent = err.response?.data?.message || 'Registration failed. Please try again.';
    } finally {
      toggleSpinner(false, 'register-button');
    }
  },
  async loginHandler(event) {
    event.preventDefault();
    const username = document.getElementById('login-username').value.trim();
    const password = document.getElementById('login-password').value.trim();
    const bypass2FA = document.getElementById('bypass-2fa-login').checked;
    const errorElement = document.getElementById('login-error');
    errorElement.textContent = '';

    if (!username || !password) {
      errorElement.textContent = 'Please fill in all fields.';
      return;
    }

    try {
      toggleSpinner(true, 'login-button');
      const response = await api.post('login', { username, password, bypass2FA });
      if (response.data.twoFactorRequired && !bypass2FA) {
        authStorage.setTempUsername(username);
        formManager.show2FA(response.data.twoFactorMethod);
      } else {
        authStorage.store(response.data.token, username);
        window.location.href = `/user/${response.data.dashboardToken}`;
      }
    } catch (err) {
      errorElement.textContent = err.response?.data?.message || 'Login failed. Please try again.';
    } finally {
      toggleSpinner(false, 'login-button');
    }
  },
  async verify2FAHandler(event) {
    event.preventDefault();
    const totpVisible = !document.getElementById('totp-container').classList.contains('hidden');
    const token = totpVisible
      ? document.getElementById('totp-token').value.trim()
      : document.getElementById('email-token').value.trim();
    const errorElement = document.getElementById('2fa-error');
    errorElement.textContent = '';
    const username = authStorage.getTempUsername();

    if (!username || !token) {
      errorElement.textContent = 'Verification failed. Please try logging in again.';
      return;
    }

    try {
      toggleSpinner(true, 'verify-2fa-button');
      const response = await api.post('verify-2fa', { username, token });
      authStorage.clear();
      authStorage.store(response.data.token, username);
      window.location.href = `/user/${response.data.dashboardToken}`;
    } catch (err) {
      errorElement.textContent = err.response?.data?.message || '2FA verification failed.';
    } finally {
      toggleSpinner(false, 'verify-2fa-button');
    }
  },
  async logoutHandler(event) {
    event.preventDefault();
    try {
      toggleSpinner(true, 'logout-button');
      const { token } = authStorage.get();
      if (token) {
        await api.post('logout', {}, { headers: { Authorization: `Bearer ${token}` } });
      }
      authStorage.clear();
      window.location.href = '/';
    } catch (err) {
      showModal('Logout failed. Please try again.');
    } finally {
      toggleSpinner(false, 'logout-button');
    }
  },
  async authenticated() {
    const { token, username } = authStorage.get();
    if (!token || !username) {
      authStorage.clear();
      formManager.show('login-form');
      return;
    }
    try {
      const response = await api.get(`user/${encodeURIComponent(username)}`, { headers: { Authorization: `Bearer ${token}` } });
      window.location.href = `/user/${response.data.dashboardToken}`;
    } catch {
      authStorage.clear();
      window.location.href = '/';
    }
  },
};

document.addEventListener('DOMContentLoaded', () => {
  const passwordInput = document.getElementById('password');
  const registerButton = document.getElementById('register-button');
  const loginButton = document.getElementById('login-button');
  const verify2FAButton = document.getElementById('verify-2fa-button');
  const logoutButton = document.getElementById('logout-button');
  const showRegisterLink = document.getElementById('show-register');
  const showLoginLink = document.getElementById('show-login');

  if (registerButton) registerButton.addEventListener('click', handlers.registerHandler);
  if (loginButton) loginButton.addEventListener('click', handlers.loginHandler);
  if (verify2FAButton) verify2FAButton.addEventListener('click', handlers.verify2FAHandler);
  if (logoutButton) logoutButton.addEventListener('click', handlers.logoutHandler);
  if (showRegisterLink) showRegisterLink.addEventListener('click', () => formManager.show('register-form'));
  if (showLoginLink) showLoginLink.addEventListener('click', () => formManager.show('login-form'));
  if (passwordInput) passwordInput.addEventListener('input', () => validatePassword(passwordInput.value));

  handlers.authenticated();
});