import axios from 'axios';
import { toggleSpinner, showModal, validatePassword } from '/public/js/script.js';

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
      username: localStorage.getItem('username')
    };
  },
  getTempUsername() {
    return localStorage.getItem('tempUsername');
  },
  setTempUsername(username) {
    localStorage.setItem('tempUsername', username);
  }
};

const formManager = {
  hideAll() {
    document.querySelectorAll('.form-section').forEach(form => form.classList.remove('active'));
  },
  show(formId) {
    this.hideAll();
    const form = document.getElementById(formId);
    if (form) form.classList.add('active');
  },
  show2FA() {
    this.show('2fa-form');
    const emailContainer = document.getElementById('email-container');
    if (emailContainer) emailContainer.classList.remove('hidden');
    startTimer();
  }
};

const api = axios.create({
  baseURL: '/api/',
  withCredentials: true
});

const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
api.defaults.headers.post['X-CSRF-Token'] = csrfToken;
api.defaults.headers.put['X-CSRF-Token'] = csrfToken;
api.defaults.headers.delete['X-CSRF-Token'] = csrfToken;

let timerInterval;
function startTimer() {
  const timerDisplay = document.getElementById('timer');
  const resendButton = document.getElementById('resend-button');
  let timeLeft = 90;
  timerDisplay.textContent = timeLeft;
  resendButton.style.display = 'none';
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = setInterval(() => {
    timeLeft--;
    timerDisplay.textContent = timeLeft;
    if (timeLeft <= 0) {
      clearInterval(timerInterval);
      timerDisplay.textContent = '0';
      resendButton.style.display = 'inline-block';
    }
  }, 1000);
}

async function resend2FACode() {
  const username = authStorage.getTempUsername();
  if (!username) return;
  try {
    toggleSpinner(true, 'verify-2fa-button');
    await api.post('resend-2fa', { username });
    startTimer();
    document.getElementById('2fa-error').textContent = 'A new code has been sent to your email.';
  } catch (err) {
    document.getElementById('2fa-error').textContent = err.response?.data?.message || 'Resending code failed.';
  } finally {
    toggleSpinner(false, 'verify-2fa-button');
  }
}

const handlers = {
  async registerHandler(event) {
    event.preventDefault();
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value.trim();
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
      const response = await api.post('register', { username, email, password });
      if (response.status === 201) {
        if (response.data.twoFactorRequired) {
          authStorage.setTempUsername(username);
          formManager.show2FA();
        } else {
          authStorage.store(response.data.token, username);
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
    const errorElement = document.getElementById('login-error');
    errorElement.textContent = '';

    if (!username || !password) {
      errorElement.textContent = 'Please fill in all fields.';
      return;
    }

    try {
      toggleSpinner(true, 'login-button');
      const response = await api.post('login', { username, password });
      if (response.data.twoFactorRequired) {
        authStorage.setTempUsername(username);
        formManager.show2FA();
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
    const token = document.getElementById('email-token').value.trim();
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
      window.location.href = '/logged-out';
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
      const response = await api.get(`user/${encodeURIComponent(username)}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      window.location.href = `/user/${response.data.dashboardToken}`;
    } catch {
      authStorage.clear();
      window.location.href = '/';
    }
  }
};

document.addEventListener('DOMContentLoaded', () => {
  const getEl = id => document.getElementById(id);
  const registerButton = getEl('register-button');
  const loginButton = getEl('login-button');
  const verify2FAButton = getEl('verify-2fa-button');
  const logoutButton = getEl('logout-button');
  const showRegisterLink = getEl('show-register');
  const showLoginLink = getEl('show-login');
  const passwordInput = getEl('password');
  const resendButton = getEl('resend-button');
  const forgotPasswordLink = getEl('forgot-password-link');
  const backToLoginLink = getEl('back-to-login');
  const sendResetLinkButton = getEl('send-reset-link');
  const themeToggleButton = document.getElementById('theme-toggle');

  function switchTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme');
    const newTheme = currentTheme === 'light' ? 'dark' : 'light';

    html.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);

    if (newTheme === 'dark') {
      themeToggleButton.querySelector('svg').innerHTML = `
        <path d="M9.598 1.591a.749.749 0 0 1 .785-.175 7.001 7.001 0 1 1-8.967 8.967.75.75 0 0 1 .961-.96 5.5 5.5 0 0 0 7.046-7.046.75.75 0 0 1 .175-.786Zm1.616 1.945a7 7 0 0 1-7.678 7.678 5.499 5.499 0 1 0 7.678-7.678Z"></path>
      `;
    } else {
      themeToggleButton.querySelector('svg').innerHTML = `
        <path d="M8 12a4 4 0 1 1 0-8 4 4 0 0 1 0 8Zm0-1.5a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5Zm5.657-8.157a.75.75 0 0 1 0 1.061l-1.061 1.06a.749.749 0 0 1-1.275-.326.749.749 0 0 1 .215-.734l1.06-1.06a.75.75 0 0 1 1.06 0Zm-9.193 9.193a.75.75 0 0 1 0 1.06l-1.06 1.061a.75.75 0 1 1-1.061-1.06l1.06-1.061a.75.75 0 0 1 1.061 0ZM8 0a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0V.75A.75.75 0 0 1 8 0ZM3 8a.75.75 0 0 1-.75.75H.75a.75.75 0 0 1 0-1.5h1.5A.75.75 0 0 1 3 8Zm13 0a.75.75 0 0 1-.75.75h-1.5a.75.75 0 0 1 0-1.5h1.5A.75.75 0 0 1 16 8Zm-8 5a.75.75 0 0 1 .75.75v1.5a.75.75 0 0 1-1.5 0v-1.5A.75.75 0 0 1 8 13Zm3.536-1.464a.75.75 0 0 1 1.06 0l1.061 1.06a.75.75 0 0 1-1.06 1.061l-1.061-1.06a.75.75 0 0 1 0-1.061ZM2.343 2.343a.75.75 0 0 1 1.061 0l1.06 1.061a.751.751 0 0 1-.018 1.042.751.751 0 0 1-1.042.018l-1.06-1.06a.75.75 0 0 1 0-1.06Z"></path>
      `;
    }
  }

  const initialTheme = localStorage.getItem('theme') || 'light';
  document.documentElement.setAttribute('data-theme', initialTheme);

  if (themeToggleButton) {
    if (initialTheme === 'dark') {
      themeToggleButton.querySelector('svg').innerHTML = `
        <path d="M9.598 1.591a.749.749 0 0 1 .785-.175 7.001 7.001 0 1 1-8.967 8.967.75.75 0 0 1 .961-.96 5.5 5.5 0 0 0 7.046-7.046.75.75 0 0 1 .175-.786Zm1.616 1.945a7 7 0 0 1-7.678 7.678 5.499 5.499 0 1 0 7.678-7.678Z"></path>
      `;
    }

    themeToggleButton.addEventListener('click', switchTheme);
  }

  if (registerButton) registerButton.addEventListener('click', handlers.registerHandler);
  if (loginButton) loginButton.addEventListener('click', handlers.loginHandler);
  if (verify2FAButton) verify2FAButton.addEventListener('click', handlers.verify2FAHandler);
  if (logoutButton) logoutButton.addEventListener('click', handlers.logoutHandler);
  if (showRegisterLink) showRegisterLink.addEventListener('click', () => formManager.show('register-form'));
  if (showLoginLink) showLoginLink.addEventListener('click', () => formManager.show('login-form'));
  if (passwordInput) passwordInput.addEventListener('input', () => validatePassword(passwordInput.value));
  if (resendButton) resendButton.addEventListener('click', async () => await resend2FACode());
  handlers.authenticated();

  if (forgotPasswordLink) {
    forgotPasswordLink.addEventListener('click', e => {
      e.preventDefault();
      formManager.show('forgot-password-form');
    });
  }
  if (backToLoginLink) {
    backToLoginLink.addEventListener('click', e => {
      e.preventDefault();
      formManager.show('login-form');
    });
  }
  if (sendResetLinkButton) {
    sendResetLinkButton.addEventListener('click', async e => {
      e.preventDefault();
      const email = getEl('forgot-email').value.trim();
      const errorElement = getEl('forgot-password-error');
      errorElement.textContent = '';
      if (!email) {
        errorElement.textContent = 'Please enter your email.';
        return;
      }
      try {
        toggleSpinner(true, 'send-reset-link');
        const response = await api.post('forgot-password', { email });
        errorElement.textContent = response.data.message;
      } catch (err) {
        errorElement.textContent = err.response?.data?.message || 'Failed to send reset link.';
      } finally {
        toggleSpinner(false, 'send-reset-link');
      }
    });
  }
});
