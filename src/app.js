import axios from 'axios';
import { toggleSpinner, showModal, validatePassword } from '@scripts/script.js';

const AUTH_TOKEN_KEY = 'authToken';
const USERNAME_KEY = 'username';
const TEMP_USERNAME_KEY = 'tempUsername';

const authStorage = {
  store(token, username) {
    try {
      localStorage.setItem(AUTH_TOKEN_KEY, token);
      localStorage.setItem(USERNAME_KEY, username);
    } catch (e) {
      console.error("Error saving to localStorage", e);
      showModal("Could not save session. Please ensure localStorage is enabled.");
    }
  },
  clear() {
    localStorage.removeItem(AUTH_TOKEN_KEY);
    localStorage.removeItem(USERNAME_KEY);
    localStorage.removeItem(TEMP_USERNAME_KEY);
  },
  get() {
    return {
      token: localStorage.getItem(AUTH_TOKEN_KEY),
      username: localStorage.getItem(USERNAME_KEY)
    };
  },
  getTempUsername() {
    return localStorage.getItem(TEMP_USERNAME_KEY);
  },
  setTempUsername(username) {
    try {
      localStorage.setItem(TEMP_USERNAME_KEY, username);
    } catch (e) {
      console.error("Error saving temp username to localStorage", e);
    }
  }
};

const formManager = {
  _activeForm: null,
  hideAll() {
    document.querySelectorAll('.form-section').forEach(form => {
      form.classList.remove('active');
      form.setAttribute('aria-hidden', 'true');
    });
    this._activeForm = null;
  },
  show(formId) {
    this.hideAll();
    const form = document.getElementById(formId);
    if (form) {
      form.classList.add('active');
      form.setAttribute('aria-hidden', 'false');
      this._activeForm = form;
      const firstInput = form.querySelector('input:not([type=hidden])');
      firstInput?.focus();
    } else {
      console.warn(`Form with ID "${formId}" not found.`);
    }
  },
  show2FA(username) {
    authStorage.setTempUsername(username);
    const faUsernameInput = document.getElementById('fa-username');
    if (faUsernameInput) {
      faUsernameInput.value = username;
    }
    this.show('fa-form');
    start2FATimer();
  },
  getActiveFormId() {
    return this._activeForm?.id;
  }
};

const api = axios.create({
  baseURL: '/api/',
  withCredentials: true,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  }
});

api.interceptors.request.use(config => {
  const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
  if (csrfToken && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(config.method?.toUpperCase())) {
    config.headers['X-CSRF-Token'] = csrfToken;
  }
  const { token } = authStorage.get();
  if (token && !config.url.endsWith('/login') && !config.url.endsWith('/register')) {
    config.headers['Authorization'] = `Bearer ${token}`;
  }
  return config;
}, error => {
  return Promise.reject(error);
});

api.interceptors.response.use(response => response, error => {
  if (error.response?.status === 401) {
    const activeForm = formManager.getActiveFormId();
    if (activeForm !== 'login-form' && activeForm !== 'register-form' && activeForm !== 'forgot-password-form') {
      console.warn("Received 401 Unauthorized. Clearing session and redirecting.");
      authStorage.clear();
      window.location.href = '/logged-out?reason=unauthorized';
    }
  }
  return Promise.reject(error);
});


let twoFATimerInterval = null;
function start2FATimer() {
  const timerDisplay = document.getElementById('timer');
  const resendButton = document.getElementById('resend-2fa-button');
  if (!timerDisplay || !resendButton) return;

  let timeLeft = 90;
  timerDisplay.textContent = `Resend available in ${timeLeft}s`;
  resendButton.disabled = true;
  resendButton.classList.add('disabled');

  if (twoFATimerInterval) clearInterval(twoFATimerInterval);

  twoFATimerInterval = setInterval(() => {
    timeLeft--;
    if (timeLeft > 0) {
      timerDisplay.textContent = `Resend available in ${timeLeft}s`;
    } else {
      clearInterval(twoFATimerInterval);
      timerDisplay.textContent = '';
      resendButton.disabled = false;
      resendButton.classList.remove('disabled');
    }
  }, 1000);
}

async function resend2FACode() {
  const username = authStorage.getTempUsername();
  const faUsernameInput = document.getElementById('fa-username')?.value;
  const effectiveUsername = username || faUsernameInput;

  if (!effectiveUsername) {
    displayError('2fa-error', 'Cannot resend code. Username not found.');
    return;
  }

  const resendButton = document.getElementById('resend-2fa-button');
  const timerDisplay = document.getElementById('timer');

  try {
    resendButton.disabled = true;
    resendButton.classList.add('disabled');
    toggleSpinner(true, 'resend-2fa-button', true);
    displayError('2fa-error', 'Sending new code...');

    await api.post('resend-2fa', { username: effectiveUsername });

    start2FATimer();
    displayError('2fa-error', 'A new code has been sent to your email.', 'success');
  } catch (err) {
    displayError('2fa-error', err.response?.data?.message || 'Resending code failed.');
    resendButton.disabled = false;
    resendButton.classList.remove('disabled');
    if (timerDisplay) timerDisplay.textContent = '';
  } finally {
    toggleSpinner(false, 'resend-2fa-button', true);
  }
}

let usernameCheckTimer = null;

async function checkUsernameAvailability(username, feedbackElement) {
  if (!username || username.length < 3 || !/^[a-zA-Z0-9_]+$/.test(username)) {
    feedbackElement.textContent = 'Invalid format (3-20 chars, A-Z, 0-9, _).';
    feedbackElement.className = 'availability-message invalid';
    return false;
  }

  feedbackElement.textContent = 'Checking...';
  feedbackElement.className = 'availability-message checking';

  try {
    const response = await api.get(`check-username-availability?username=${encodeURIComponent(username)}`);

    if (response.data?.available === true) {
      feedbackElement.textContent = 'Username available';
      feedbackElement.className = 'availability-message valid';
      return true;
    } else {
      feedbackElement.textContent = response.data?.message || 'Username not available';
      feedbackElement.className = 'availability-message invalid';
      return false;
    }
  } catch (err) {
    console.error('Error checking username availability:', err);
    feedbackElement.textContent = 'Could not check availability';
    feedbackElement.className = 'availability-message error';
    return false;
  }
}

function displayError(elementId, message, type = 'error') {
  const errorElement = document.getElementById(elementId);
  if (errorElement) {
    errorElement.textContent = message;
    errorElement.className = type;
    errorElement.setAttribute('role', type === 'error' ? 'alert' : 'status');
  }
}

const handlers = {
  async register(event) {
    event.preventDefault();
    const usernameInput = document.getElementById('username');
    const emailInput = document.getElementById('email');
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirmPassword');
    const feedbackElement = document.getElementById('username-availability-message');
    const registerButton = document.getElementById('register-button');

    displayError('register-error', '');

    const username = usernameInput.value.trim();
    const email = emailInput.value.trim();
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    if (!username || !email || !password || !confirmPassword) {
      displayError('register-error', 'Please fill in all fields.');
      return;
    }
    if (password !== confirmPassword) {
      displayError('register-error', 'Passwords do not match.');
      return;
    }
    if (!validatePassword(password)) {
      displayError('register-error', 'Password does not meet the requirements.');
      return;
    }

    toggleSpinner(true, registerButton);
    let isUsernameAvailable = false;
    try {
      isUsernameAvailable = await checkUsernameAvailability(username, feedbackElement);
      if (!isUsernameAvailable) {
        displayError('register-error', feedbackElement.textContent || 'Username is not available.');
        toggleSpinner(false, registerButton);
        return;
      }

      const response = await api.post('register', { username, email, password, confirmPassword });

      if (response.status === 201) {
        if (response.data.twoFactorRequired) {
          formManager.show2FA(username);
        } else if (response.data.token && response.data.redirectUrl) {
          authStorage.store(response.data.token, username);
          window.location.href = response.data.redirectUrl;
        } else {
          console.error("Registration response missing token or redirect URL", response.data);
          displayError('register-error', 'Registration completed but failed to log in. Please try logging in manually.');
          formManager.show('login-form');
        }
      } else {
        displayError('register-error', `Unexpected status code: ${response.status}`);
      }
    } catch (err) {
      console.error('Registration error:', err);
      if (err.response?.data?.message?.toLowerCase().includes('username') && err.response?.data?.message?.toLowerCase().includes('taken')) {
        feedbackElement.textContent = 'Username not available';
        feedbackElement.className = 'availability-message invalid';
        displayError('register-error', 'Username is not available. Please choose another.');
      } else {
        displayError('register-error', err.response?.data?.message || 'Registration failed. Please try again.');
      }
    } finally {
      if (!window.location.pathname.startsWith('/user/')) {
        toggleSpinner(false, registerButton);
      }
    }
  },

  async login(event) {
    event.preventDefault();
    const usernameInput = document.getElementById('login-username');
    const passwordInput = document.getElementById('login-password');
    const loginButton = document.getElementById('login-button');

    displayError('login-error', '');

    const username = usernameInput.value.trim();
    const password = passwordInput.value;

    if (!username || !password) {
      displayError('login-error', 'Please provide both username and password.');
      return;
    }

    try {
      toggleSpinner(true, loginButton);
      const response = await api.post('login', { username, password });

      if (response.data.twoFactorRequired) {
        formManager.show2FA(username);
      } else if (response.data.token && response.data.redirectUrl) {
        authStorage.store(response.data.token, username);
        window.location.href = response.data.redirectUrl;
      } else {
        console.error("Login response missing token or redirect URL", response.data);
        displayError('login-error', 'Login succeeded but failed to redirect. Please try again.');
      }
    } catch (err) {
      console.error('Login error:', err);
      displayError('login-error', err.response?.data?.message || 'Login failed. Please check your credentials.');
    } finally {
      if (!window.location.pathname.startsWith('/user/')) {
        toggleSpinner(false, loginButton);
      }
    }
  },

  async verify2FA(event) {
    event.preventDefault();
    const tokenInput = document.getElementById('email-token');
    const username = document.getElementById('fa-username').value;
    const verifyButton = document.getElementById('verify-2fa-button');

    displayError('2fa-error', '');
    const token = tokenInput.value.trim();

    if (!username) {
      displayError('2fa-error', 'Verification failed. Username missing. Please log in again.');
      formManager.show('login-form');
      return;
    }
    if (!token || token.length !== 6) {
      displayError('2fa-error', 'Please enter the 6-digit verification code.');
      return;
    }

    try {
      toggleSpinner(true, verifyButton);
      const response = await api.post('verify-2fa', { username, token });

      if (response.data.token && response.data.redirectUrl) {
        authStorage.clear();
        authStorage.store(response.data.token, username);
        window.location.href = response.data.redirectUrl;
      } else {
        console.error("2FA verification response missing token or redirect URL", response.data);
        displayError('2fa-error', 'Verification succeeded but failed to complete login. Please try logging in again.');
        formManager.show('login-form');
      }
    } catch (err) {
      console.error('2FA verification error:', err);
      displayError('2fa-error', err.response?.data?.message || 'Invalid or expired verification code.');
    } finally {
      if (!window.location.pathname.startsWith('/user/')) {
        toggleSpinner(false, verifyButton);
      }
    }
  },

  async forgotPassword(event) {
    event.preventDefault();
    const emailInput = document.getElementById('forgot-email');
    const sendButton = document.getElementById('send-reset-link');
    const messageElement = document.getElementById('forgot-password-message'); // Still used by displayError

    displayError('forgot-password-message', '', 'message');
    const email = emailInput.value.trim();

    if (!email) {
      displayError('forgot-password-message', 'Please enter your email address.');
      return;
    }

    try {
      toggleSpinner(true, sendButton);
      const response = await api.post('forgot-password', { email });
      displayError('forgot-password-message', response.data.message, 'success');
      emailInput.value = '';
    } catch (err) {
      console.error('Forgot password error:', err);
      displayError('forgot-password-message', err.response?.data?.message || 'Failed to send reset link. Please try again.');
    } finally {
      toggleSpinner(false, sendButton);
    }
  },

  async checkAuthOnLoad() {
    const { token, username: storedUsername } = authStorage.get();
    const isOnPublicPage = ['/', '/index.html', '/logged-out'].includes(window.location.pathname) || window.location.pathname.startsWith('/reset-password');

    if (!token || !storedUsername) {
      authStorage.clear();
      if (!isOnPublicPage) {
        console.log("No token/username, redirecting from protected page.");
        window.location.href = '/?reason=noAuth';
      } else if (window.location.pathname === '/' || window.location.pathname === '/index.html') {
        if (!formManager.getActiveFormId() || formManager.getActiveFormId() === 'login-form') {
          formManager.show('login-form');
        }
      }
      return;
    }

    if ((isOnPublicPage && !window.location.pathname.startsWith('/logged-out') && !window.location.pathname.startsWith('/reset-password')) || !isOnPublicPage) {
      try {
        console.log("Checking auth with token...");
        const response = await api.get('check-auth');

        if (response.data?.ok && response.data.username === storedUsername) {
          console.log("Auth check successful.");
          if (window.location.pathname === '/' || window.location.pathname === '/index.html') {
            console.log("User on index page but logged in, redirecting to dashboard.");
            window.location.href = '/dashboard';
          }
        } else {
          throw new Error("Auth check failed or username mismatch.");
        }
      } catch (err) {
        console.warn('Auth check failed, clearing storage.', err.response?.status, err.message);
        authStorage.clear();
        if (!isOnPublicPage) {
          window.location.href = '/?reason=invalidAuth';
        } else if (window.location.pathname === '/' || window.location.pathname === '/index.html') {
          formManager.show('login-form');
        }
      }
    }
  }
};

function setupEventListeners() {
  const getEl = id => document.getElementById(id);

  const registerForm = getEl('register-form');
  const loginForm = getEl('login-form');
  const verify2FAForm = getEl('fa-form');
  const forgotPasswordForm = getEl('forgot-password-form');

  const passwordInput = getEl('password');
  const usernameInput = getEl('username');
  const resend2FAButton = getEl('resend-2fa-button');
  const themeToggleButton = getEl('theme-toggle'); // This one IS used

  if (registerForm) registerForm.addEventListener('submit', handlers.register);
  if (loginForm) loginForm.addEventListener('submit', handlers.login);
  if (verify2FAForm) verify2FAForm.addEventListener('submit', handlers.verify2FA);
  if (forgotPasswordForm) forgotPasswordForm.addEventListener('submit', handlers.forgotPassword);

  document.querySelectorAll('button[data-form-target]').forEach(button => {
    button.addEventListener('click', (e) => {
      e.preventDefault();
      const targetFormId = button.getAttribute('data-form-target');
      if (targetFormId) {
        formManager.show(targetFormId);
      }
    });
  });

  if (passwordInput) passwordInput.addEventListener('input', () => validatePassword(passwordInput.value));
  if (resend2FAButton) resend2FAButton.addEventListener('click', resend2FACode);

  if (usernameInput) {
    const feedbackElement = getEl('username-availability-message');
    if (feedbackElement) {
      usernameInput.addEventListener('input', () => {
        clearTimeout(usernameCheckTimer);
        const username = usernameInput.value.trim();
        const constraintsElement = getEl('username-constraints');

        if (!username) {
          feedbackElement.textContent = '';
          feedbackElement.className = 'availability-message';
          if (constraintsElement) constraintsElement.classList.add('visually-hidden');
          return;
        }
        if (username.length < 3 || !/^[a-zA-Z0-9_]+$/.test(username)) {
          feedbackElement.textContent = 'Invalid format (3-20 chars, A-Z, 0-9, _).';
          feedbackElement.className = 'availability-message invalid';
          if (constraintsElement) constraintsElement.classList.remove('visually-hidden');
          clearTimeout(usernameCheckTimer);
          return;
        }

        if (constraintsElement) constraintsElement.classList.add('visually-hidden');
        feedbackElement.textContent = 'Checking...';
        feedbackElement.className = 'availability-message checking';

        usernameCheckTimer = setTimeout(() => {
          checkUsernameAvailability(username, feedbackElement);
        }, 500);
      });
    }
  }

  if (themeToggleButton) {
    themeToggleButton.addEventListener('click', () => {
      const currentTheme = document.documentElement.getAttribute('data-theme');
      const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', newTheme);
      try {
        localStorage.setItem('theme', newTheme);
      } catch (e) {
        console.warn("Could not save theme preference to localStorage", e);
      }
    });
  }
}

function initializeTheme() {
  let theme = 'light';
  try {
    theme = localStorage.getItem('theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  } catch (e) {
    console.warn("Could not read theme preference from localStorage", e);
    theme = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  document.documentElement.setAttribute('data-theme', theme);
}

document.addEventListener('DOMContentLoaded', () => {
  initializeTheme();
  setupEventListeners();
  handlers.checkAuthOnLoad();
});
