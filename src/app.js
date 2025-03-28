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
    this.show('fa-form');
    const emailContainer = document.getElementById('email-container');
    if (emailContainer) {
      emailContainer.classList.remove('hidden');
    }
    const timerEl = document.getElementById('timer');
    const resendButtonEl = document.getElementById('resend-button');
    if (timerEl && resendButtonEl) {
      startTimer();
    }
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
api.defaults.headers.get['X-CSRF-Token'] = csrfToken;

let timerInterval;
function startTimer() {
  const timerDisplay = document.getElementById('timer');
  const resendButton = document.getElementById('resend-button');
  if (!timerDisplay || !resendButton) return;
  
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
  
  const errorEl = document.getElementById('2fa-error');
  if (!errorEl) return;
  
  try {
    toggleSpinner(true, 'verify-2fa-button');
    await api.post('resend-2fa', { username });
    startTimer();
    errorEl.textContent = 'A new code has been sent to your email.';
  } catch (err) {
    errorEl.textContent = err.response?.data?.message || 'Resending code failed.';
  } finally {
    toggleSpinner(false, 'verify-2fa-button');
  }
}

let usernameCheckTimer = null;
async function checkUsernameAvailability(username, feedbackElement) {
  if (!username || username.length < 3) {
    feedbackElement.textContent = '';
    feedbackElement.className = 'username-feedback';
    return false; // Username too short
  }
  
  try {
    const response = await api.get(
      `check-username-availability?username=${encodeURIComponent(username)}`
    );
    
    // Check if the response has the expected structure
    if (response.data && typeof response.data.available === 'boolean') {
      if (response.data.available) {
        feedbackElement.textContent = 'Username available';
        feedbackElement.className = 'username-feedback valid';
        return true;
      } else {
        feedbackElement.textContent = 'Username already taken';
        feedbackElement.className = 'username-feedback invalid';
        return false;
      }
    } else {
      console.warn('Unexpected response format:', response.data);
      // Don't mark as invalid if the response is unexpected
      feedbackElement.textContent = '';
      feedbackElement.className = 'username-feedback';
      return true; // Let the server decide during registration
    }
  } catch (err) {
    console.error('Error checking username:', err);
    // Don't mark as invalid on network errors
    feedbackElement.textContent = 'Could not verify availability';
    feedbackElement.className = 'username-feedback';
    return true; // Let the server decide during registration
  }
}

const handlers = {
  async registerHandler(event) {
    event.preventDefault();
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    const password = document.getElementById('password').value.trim();
    const confirmPassword = document.getElementById('confirm-password')?.value.trim();
    const errorElement = document.getElementById('register-error');
    const feedbackElement = document.getElementById('username-feedback');
    
    errorElement.textContent = '';

    if (!username || !email || !password) {
      errorElement.textContent = 'Please fill in all fields.';
      return;
    }

    if (confirmPassword && password !== confirmPassword) {
      errorElement.textContent = 'Passwords do not match.';
      return;
    }

    if (!validatePassword(password)) {
      errorElement.textContent = 'Password does not meet the requirements.';
      return;
    }

    // Only check if the feedback explicitly says the username is invalid
    if (feedbackElement && feedbackElement.className === 'username-feedback invalid') {
      errorElement.textContent = 'Please choose a different username.';
      return;
    }

    try {
      toggleSpinner(true, 'register-button');
      
      // Remove the duplicate availability check - rely on the server
      // to provide the final decision
      
      const response = await api.post('register', { 
        username, 
        email, 
        password,
        confirmPassword: confirmPassword || password
      });
      
      if (response.status === 201) {
        if (response.data.twoFactorRequired) {
          authStorage.setTempUsername(username);
          formManager.show2FA();
        } else {
          authStorage.store(response.data.token, username);
          
          if (response.data.redirectUrl) {
            window.location.href = response.data.redirectUrl;
          } else {
            try {
              window.location.href = `/dashboard/${response.data.dashboardToken}`;
            } catch (e) {
              window.location.href = `/user/${response.data.dashboardToken}`;
            }
          }
        }
      }
    } catch (err) {
      console.error('Registration error:', err);
      // Provide more specific error messages based on the response
      if (err.response && err.response.data && err.response.data.message) {
        errorElement.textContent = err.response.data.message;
      } else {
        errorElement.textContent = 'Registration failed. Please try again.';
      }
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
        
        if (response.data.redirectUrl) {
          window.location.href = response.data.redirectUrl;
        } else {
          try {
            window.location.href = `/dashboard/${response.data.dashboardToken}`;
          } catch (e) {
            window.location.href = `/user/${response.data.dashboardToken}`;
          }
        }
      }
    } catch (err) {
      console.error('Login error:', err);
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

      if (response.data.redirectUrl) {
        window.location.href = response.data.redirectUrl;
      } else {
        try {
          window.location.href = `/dashboard/${response.data.dashboardToken}`;
        } catch (e) {
          window.location.href = `/user/${response.data.dashboardToken}`;
        }
      }
    } catch (err) {
      console.error('2FA verification error:', err);
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
      console.error('Logout error:', err);
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
      
      if (response.data.redirectUrl) {
        window.location.href = response.data.redirectUrl;
      } else if (response.data.dashboardToken) {
        try {
          window.location.href = `/dashboard/${response.data.dashboardToken}`;
        } catch (e) {
          window.location.href = `/user/${response.data.dashboardToken}`;
        }
      } else {
        authStorage.clear();
        formManager.show('login-form');
      }
    } catch (err) {
      console.error('Authentication check error:', err);
      authStorage.clear();
      formManager.show('login-form');
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
  const usernameInput = getEl('username');
  const resendButton = getEl('resend-button');
  const forgotPasswordLink = getEl('forgot-password-link');
  const backToLoginLink = getEl('back-to-login');
  const sendResetLinkButton = getEl('send-reset-link');
  const themeToggleButton = document.getElementById('theme-toggle');

  if (usernameInput) {
    const feedbackElement = document.createElement('div');
    feedbackElement.id = 'username-feedback';
    feedbackElement.className = 'username-feedback';
    usernameInput.parentNode.insertBefore(feedbackElement, usernameInput.nextSibling);
    
    usernameInput.addEventListener('input', () => {
      clearTimeout(usernameCheckTimer);
      const username = usernameInput.value.trim();
      
      if (!username || username.length < 3) {
        feedbackElement.textContent = username ? 'Username too short (min 3 characters)' : '';
        feedbackElement.className = 'username-feedback';
        return;
      }
      
      feedbackElement.textContent = 'Checking availability...';
      feedbackElement.className = 'username-feedback checking';
      
      usernameCheckTimer = setTimeout(() => {
        checkUsernameAvailability(username, feedbackElement);
      }, 500);
    });
  }

  function setupTheme() {
    // Remove hardcoded data-theme if it exists
    if (document.documentElement.hasAttribute('data-theme')) {
      document.documentElement.removeAttribute('data-theme');
    }
    
    const initialTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', initialTheme);

    if (themeToggleButton) {
      themeToggleButton.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        console.log(`Theme changed to ${newTheme} mode at ${new Date().toISOString()}`);
      });
    }
  }

  setupTheme();

  if (registerButton) registerButton.addEventListener('click', handlers.registerHandler);
  if (loginButton) loginButton.addEventListener('click', handlers.loginHandler);
  if (verify2FAButton) verify2FAButton.addEventListener('click', handlers.verify2FAHandler);
  if (logoutButton) logoutButton.addEventListener('click', handlers.logoutHandler);
  if (showRegisterLink) showRegisterLink.addEventListener('click', () => formManager.show('register-form'));
  if (showLoginLink) showLoginLink.addEventListener('click', () => formManager.show('login-form'));
  if (passwordInput) passwordInput.addEventListener('input', () => validatePassword(passwordInput.value));
  if (resendButton) resendButton.addEventListener('click', async () => await resend2FACode());

  if (window.location.pathname === '/' || window.location.pathname === '/index.html') {
    const formSections = document.querySelectorAll('.form-section');
    if (formSections.length > 0) {
      handlers.authenticated();
    }
  }

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
  
  console.log(`Auth System v1.5.4 | © 2025 cgtwig | Last Updated: 2025-03-13 12:01:57`);
  console.log(`Current user: ${authStorage.get().username || 'cgtwigThis'}`);
});
