/**
 * @fileoverview User dashboard functionality and settings management
 * @version 1.5.7
 * @lastModified 2025-03-13 12:44:24 UTC
 * @author cgtwig
 */

// Set initial theme before DOM loads to prevent flash of incorrect theme
(function() {
  const savedTheme = localStorage.getItem('theme') || 'light';
  document.documentElement.setAttribute('data-theme', savedTheme);
})();

document.addEventListener('DOMContentLoaded', () => {
  class DashboardManager {
    constructor() {
      this.csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
      this.setupEventHandlers();
      this.setupThemeToggle();
      this.checkAuth();
      this.typingTimer = null;
      this.doneTypingInterval = 500;
      this.updateDateTime();
      
      // Set up timer to update date/time periodically
      setInterval(() => this.updateDateTime(), 30000);
    }

    setupThemeToggle() {
      const themeToggleBtn = document.getElementById('theme-toggle');
      if (!themeToggleBtn) {
        console.error('Theme toggle button not found');
        return;
      }

      themeToggleBtn.addEventListener('click', () => {
        // Get current theme and determine new theme
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        
        // Update HTML attribute and localStorage
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        console.log(`Theme changed to ${newTheme} mode at ${this.formatUTCDate(new Date())}`);
      });
    }

    updateDateTime() {
      const datetimeEl = document.getElementById('datetime');
      if (datetimeEl) {
        const now = new Date();
        const formattedDate = this.formatUTCDate(now);
        datetimeEl.textContent = formattedDate;
      }
    }

    formatUTCDate(date) {
      const year = date.getUTCFullYear();
      const month = String(date.getUTCMonth() + 1).padStart(2, '0');
      const day = String(date.getUTCDate()).padStart(2, '0');
      const hours = String(date.getUTCHours()).padStart(2, '0');
      const minutes = String(date.getUTCMinutes()).padStart(2, '0');
      const seconds = String(date.getUTCSeconds()).padStart(2, '0');
      return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    }

    async checkAuth() {
      try {
        const response = await fetch('/api/check-auth', { 
          method: 'GET', 
          credentials: 'same-origin',
          headers: { 'X-CSRF-Token': this.csrfToken }
        });
        if (!response.ok) throw new Error('Authentication failed');
      } catch (e) {
        console.error('Authentication check failed:', e);
      }
    }

    handleLogout() {
      localStorage.clear();
      sessionStorage.clear();
      window.location.href = '/logged-out';
    }

    setupEventHandlers() {
      const logoutButton = document.getElementById('logout-button');
      if (logoutButton) {
        logoutButton.addEventListener('click', () => this.logoutHandler());
      }
      const editButtons = document.querySelectorAll('.edit-button');
      editButtons.forEach(button => {
        button.addEventListener('click', () => this.handleEditClick(button));
      });
    }

    logoutHandler() {
      try {
        fetch('/api/logout', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 
            'Content-Type': 'application/json',
            'X-CSRF-Token': this.csrfToken
          }
        }).then(() => this.handleLogout())
          .catch(e => { console.error('Logout failed', e); this.handleLogout(); });
      } catch (e) {
        console.error('Logout failed', e);
        this.handleLogout();
      }
    }

    handleEditClick(button) {
      const setting = button.getAttribute('data-setting');
      const row = document.querySelector(`tr[data-setting="${setting}"]`);
      if (!row) return;

      const displayValue = row.querySelector('.display-value');
      const inputs = row.querySelectorAll('.edit-input');

      displayValue.classList.add('hidden');
      inputs.forEach(input => {
        input.dataset.originalValue = input.value;
        input.classList.remove('hidden');
        input.focus();
      });

      button.classList.remove('edit-button');
      button.classList.add('save-button');
      button.setAttribute('title', 'Save changes');
      button.innerHTML = `
        <svg class="colorFill" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="12" height="12">
          <path d="M13.78 4.22a.75.75 0 0 1 0 1.06l-7.25 7.25a.75.75 0 0 1-1.06 0L2.22 9.28a.751.751 0 0 1 .018-1.042.751.751 0 0 1 1.042-.018L6 10.94l6.72-6.72a.75.75 0 0 1 1.06 0Z"></path>
        </svg>`;
      const newButton = button.cloneNode(true);
      button.parentNode.replaceChild(newButton, button);
      newButton.addEventListener('click', () => this.handleSaveClick(setting, row, newButton));

      if (setting === 'username') {
        let feedbackElement = row.querySelector('.username-feedback');
        if (!feedbackElement) {
          feedbackElement = document.createElement('div');
          feedbackElement.className = 'username-feedback';
          inputs[0].parentNode.insertBefore(feedbackElement, inputs[0].nextSibling);
        }
        feedbackElement.textContent = '';
        feedbackElement.className = 'username-feedback';
        inputs[0].addEventListener('input', () => {
          clearTimeout(this.typingTimer);
          const username = inputs[0].value.trim();
          if (!username) {
            feedbackElement.textContent = '';
            feedbackElement.className = 'username-feedback';
            return;
          }
          feedbackElement.textContent = 'Checking availability...';
          feedbackElement.className = 'username-feedback checking';
          this.typingTimer = setTimeout(() => {
            this.checkUsernameAvailability(username, feedbackElement, inputs[0]);
          }, this.doneTypingInterval);
        });
      }
    }

    async checkUsernameAvailability(username, feedbackElement, input) {
      try {
        const response = await fetch(
          `/api/check-username-availability?username=${encodeURIComponent(username)}`, {
          method: 'GET',
          credentials: 'same-origin',
          headers: {
            'Accept': 'application/json',
            'X-CSRF-Token': this.csrfToken
          }
        });
        const result = await response.json();
        if (response.ok) {
          if (result.available) {
            feedbackElement.textContent = 'Username available';
            feedbackElement.className = 'username-feedback valid';
            input.dataset.isValid = 'true';
          } else {
            feedbackElement.textContent = 'Username already taken';
            feedbackElement.className = 'username-feedback invalid';
            input.dataset.isValid = 'false';
          }
        } else {
          feedbackElement.textContent = result.message || 'Error checking availability';
          feedbackElement.className = 'username-feedback error';
          input.dataset.isValid = 'false';
        }
      } catch (error) {
        console.error('Error checking username:', error);
        feedbackElement.textContent = 'Error checking availability';
        feedbackElement.className = 'username-feedback error';
        input.dataset.isValid = 'false';
      }
    }

    handleSaveClick(setting, row, button) {
      const inputs = row.querySelectorAll('.edit-input');
      const values = Array.from(inputs).map(i => i.value.trim());
      if (setting === 'username') {
        const feedbackElement = row.querySelector('.username-feedback');
        if (feedbackElement && feedbackElement.className.includes('invalid')) {
          this.showMessage('Invalid username. Please choose another.', 'error');
          return;
        }
      }
      if (setting === 'password' && values[0] !== values[1]) {
        this.showMessage('Passwords do not match', 'error');
        return;
      }
      this.updateSetting(setting, values, row, button);
    }

    async updateSetting(setting, values, row, saveButton) {
      let payload = { setting, value: '' };
      if (setting === 'password') {
        payload.value = values[0];
      } else {
        payload.value = values[0];
      }

      try {
        const response = await fetch('/api/settings/update', {
          method: 'POST',
          credentials: 'same-origin',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': this.csrfToken
          },
          body: JSON.stringify(payload)
        });

        if (!response.ok) {
          const result = await response.json();
          throw new Error(result.message || 'Update failed');
        }

        this.showMessage(`${setting} updated successfully`, 'success');
        if (setting !== 'password') {
          row.querySelector('.display-value').textContent = payload.value || 'Not set';
        }
        row.querySelectorAll('.edit-input').forEach(input => input.classList.add('hidden'));
        row.querySelector('.display-value').classList.remove('hidden');

        saveButton.classList.remove('save-button');
        saveButton.classList.add('edit-button');
        saveButton.setAttribute('title', `Edit ${setting}`);
        saveButton.innerHTML = `
          <svg class="colorFill" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="12" height="12">
            <path d="M11.013 1.427a1.75 1.75 0 0 1 2.474 0l1.086 1.086a1.75 1.75 0 0 1 0 2.474l-8.61 8.61c-.21.21-.47.364-.756.445l-3.251.93a.75.75 0 0 1-.927-.928l.929-3.25c.081-.286.235-.547.445-.758l8.61-8.61Z"></path>
          </svg>`;
        const newButton = saveButton.cloneNode(true);
        saveButton.parentNode.replaceChild(newButton, saveButton);
        newButton.addEventListener('click', () => this.handleEditClick(newButton));

        const feedbackElement = row.querySelector('.username-feedback');
        if (feedbackElement) feedbackElement.remove();
        if (setting === 'username') {
          const userInfoElement = document.getElementById('user-info');
          if (userInfoElement) {
            userInfoElement.innerHTML = `Logged in as <strong>${payload.value}</strong>`;
          }
        }
        const lastUpdatedEl = document.getElementById('last-updated');
        if (lastUpdatedEl) {
          lastUpdatedEl.textContent = this.formatUTCDate(new Date());
        }
      } catch (error) {
        console.error('Error updating setting:', error);
        this.showMessage(error.message, 'error');
      }
    }

    showMessage(message, type) {
      const msgDiv = document.createElement('div');
      msgDiv.textContent = message;
      msgDiv.className = `${type}-message`;
      document.body.appendChild(msgDiv);
      setTimeout(() => msgDiv.remove(), 3000);
    }
  }
  
  new DashboardManager();
  console.log(`Auth System v1.5.7 | © 2025 cgtwig | Last Updated: 2025-03-13 12:44:24`);
  
  // Use the username from the DOM as it's already rendered server-side
  const userInfoElement = document.getElementById('user-info');
  const usernameElement = userInfoElement?.querySelector('strong');
  const username = usernameElement?.textContent || 'Not logged in';
  console.log(`Current user: ${username}`);
});
