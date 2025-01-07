import axios from 'axios';
import { showModal, toggleSpinner } from '../public/js/script.js';

function storeAuthData(token, username) {
  localStorage.setItem('authToken', token);
  localStorage.setItem('username', username);
}

function clearAuthData() {
  localStorage.removeItem('authToken');
  localStorage.removeItem('username');
}

function getStoredAuthData() {
  return {
    token: localStorage.getItem('authToken'),
    username: localStorage.getItem('username'),
  };
}

function hideAllForms() {
  document.querySelectorAll('.form-section').forEach(f => f.classList.remove('active'));
}

function switchToForm(formId) {
  hideAllForms();
  document.getElementById(formId).classList.add('active');
}

function switchTo2FAVerification(twoFactorMethod) {
  switchToForm('2fa-form');
  const totpContainer = document.getElementById('totp-container');
  const emailContainer = document.getElementById('email-container');
  if (twoFactorMethod === 'totp') {
    totpContainer.classList.remove('hidden');
    emailContainer.classList.add('hidden');
  } else {
    totpContainer.classList.add('hidden');
    emailContainer.classList.remove('hidden');
  }
}

async function switchToAuthenticatedForm() {
  const { token, username } = getStoredAuthData();
  if (!token || !username) {
    clearAuthData();
    switchToForm('login-form');
    return;
  }
  try {
    await axios.get(`/user/${username}`, { headers: { Authorization: `Bearer ${token}` } });
    window.location.href = `/user/${username}?token=${token}`;
  } catch {
    clearAuthData();
    switchToForm('login-form');
  }
}

async function handleRegister(e) {
  e.preventDefault();
  const registerButton = document.getElementById('register-button');
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value.trim();
  const twoFactorMethod = document.getElementById('2fa-method').value;
  const bypass2FA = document.getElementById('bypass-2fa-register').checked;
  const errorElement = document.getElementById('register-error');
  errorElement.textContent = '';
  if (!username || !password) {
    errorElement.textContent = 'Please fill in all fields.';
    return;
  }
  if (password.length < 8) {
    errorElement.textContent = 'Password must be at least 8 characters.';
    return;
  }
  try {
    toggleSpinner(true, 'register-button');
    const response = await axios.post('/register', { username, password, twoFactorMethod, bypass2FA });
    if (response.status === 201) {
      storeAuthData(response.data.token, username);
      if (!bypass2FA && response.data.twoFactorMethod) {
        localStorage.setItem('tempUsername', username);
        switchTo2FAVerification(response.data.twoFactorMethod);
      } else {
        switchToAuthenticatedForm();
      }
    }
  } catch (err) {
    errorElement.textContent = err.response?.data?.message || 'Registration failed. Please try again.';
  } finally {
    toggleSpinner(false, 'register-button');
  }
}

async function handleLogin(e) {
  e.preventDefault();
  const loginButton = document.getElementById('login-button');
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
    const response = await axios.post('/login', { username, password, bypass2FA });
    if (response.data.twoFactorRequired && !bypass2FA) {
      localStorage.setItem('tempUsername', username);
      switchTo2FAVerification(response.data.twoFactorMethod);
    } else {
      storeAuthData(response.data.token, username);
      switchToAuthenticatedForm();
    }
  } catch (err) {
    errorElement.textContent = err.response?.data?.message || 'Login failed. Please try again.';
  } finally {
    toggleSpinner(false, 'login-button');
  }
}

async function handle2FAVerification(e) {
  e.preventDefault();
  const totpContainer = document.getElementById('totp-container');
  const token = !totpContainer.classList.contains('hidden')
    ? document.getElementById('totp-token').value.trim()
    : document.getElementById('email-token').value.trim();
  const errorElement = document.getElementById('2fa-error');
  errorElement.textContent = '';
  const username = localStorage.getItem('tempUsername');
  if (!username || !token) {
    errorElement.textContent = 'Verification failed. Please try logging in again.';
    return;
  }
  try {
    toggleSpinner(true, 'verify-2fa-button');
    const response = await axios.post('/verify-2fa', { username, token });
    localStorage.removeItem('tempUsername');
    storeAuthData(response.data.token, username);
    switchToAuthenticatedForm();
  } catch (err) {
    errorElement.textContent = err.response?.data?.message || '2FA verification failed.';
  } finally {
    toggleSpinner(false, 'verify-2fa-button');
  }
}

async function handleLogout() {
  try {
    toggleSpinner(true, 'logout-button');
    clearAuthData();
    switchToForm('login-form');
  } finally {
    toggleSpinner(false, 'logout-button');
  }
}

document.getElementById('register-button').addEventListener('click', handleRegister);
document.getElementById('login-button').addEventListener('click', handleLogin);
document.getElementById('verify-2fa-button').addEventListener('click', handle2FAVerification);
document.getElementById('logout-button').addEventListener('click', handleLogout);
document.getElementById('show-register').addEventListener('click', () => switchToForm('register-form'));
document.getElementById('show-login').addEventListener('click', () => switchToForm('login-form'));

window.addEventListener('load', () => {
  switchToAuthenticatedForm();
});