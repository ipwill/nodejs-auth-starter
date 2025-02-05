document.addEventListener('DOMContentLoaded', function () {
  const settingsButton = document.getElementById('settings-button');
  const backToDashboardButton = document.getElementById('back-to-dashboard');
  const dashboardSection = document.getElementById('dashboard-section');
  const settingsSection = document.getElementById('settings-section');
  const logoutButton = document.getElementById('logout-button');

  async function checkAuth() {
    try {
      const response = await fetch('/api/check-auth', { method: 'GET', credentials: 'same-origin' });
      if (!response.ok) {
        localStorage.clear();
        sessionStorage.clear();
        window.location.href = '/logged-out';
      }
    } catch (error) {
      localStorage.clear();
      sessionStorage.clear();
      window.location.href = '/logged-out';
    }
  }

  checkAuth();

  if (logoutButton) {
    logoutButton.addEventListener('click', async () => {
      try {
        await fetch('/api/logout', { method: 'POST', credentials: 'same-origin' });
      } catch (error) { }
      localStorage.clear();
      sessionStorage.clear();
      window.location.href = '/logged-out';
    });
  }

  if (settingsButton) {
    settingsButton.addEventListener('click', () => {
      dashboardSection.style.display = 'none';
      settingsSection.style.display = 'block';
    });
  }

  if (backToDashboardButton) {
    backToDashboardButton.addEventListener('click', () => {
      settingsSection.style.display = 'none';
      dashboardSection.style.display = 'block';
    });
  }

  // Settings table interaction
  const settingsTable = document.querySelector('.settings-table');
  if (settingsTable) {
    settingsTable.addEventListener('click', (e) => {
      const target = e.target.closest('.setting-value.editable, .setting-value.toggle');
      if (!target) return;
      const setting = target.getAttribute('data-setting');

      if (setting === 'email') {
        const displayValue = target.querySelector('.display-value');
        const input = target.querySelector('.edit-input');
        const saveButton = target.querySelector('.save-email-button');
        // If the editor is already open, do nothing
        if (!input.classList.contains('hidden')) return;
        displayValue.classList.add('hidden');
        input.classList.remove('hidden');
        saveButton.classList.remove('hidden');
        input.focus();
      } else if (target.classList.contains('toggle')) {
        const currentSpan = target.querySelector('span');
        if (!currentSpan) return;
        const currentValue = currentSpan.textContent.trim().toLowerCase();
        const newValue = currentValue === 'true' ? 'False' : 'True';
        currentSpan.textContent = newValue;
      }
    });
  }

  // Save button functionality for email update
  const saveEmailButtons = document.querySelectorAll('.save-email-button');
  saveEmailButtons.forEach(button => {
    button.addEventListener('click', async function () {
      const parent = button.closest('.setting-value.editable');
      const input = parent.querySelector('.edit-input');
      const displayValue = parent.querySelector('.display-value');
      const newEmail = input.value.trim();
      const existingEmails = displayValue.textContent.trim();
      const setting = parent.getAttribute('data-setting');

      try {
        const response = await fetch('/api/settings/update', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'CSRF-Token': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
          },
          // Instead of replacing, send both the existing and new email so the server can append.
          body: JSON.stringify({ setting, existing: existingEmails, value: newEmail })
        });

        if (response.ok) {
          // Append the new email separated by a comma.
          displayValue.textContent = existingEmails + ', ' + newEmail;
          input.classList.add('hidden');
          button.classList.add('hidden');
          displayValue.classList.remove('hidden');
        } else {
          throw new Error('Failed to update email');
        }
      } catch (error) {
        console.error('Error updating email:', error);
        input.classList.add('hidden');
        button.classList.add('hidden');
        displayValue.classList.remove('hidden');
      }
    });
  });

  // Handling non-email editable fields
  const editableFields = document.querySelectorAll('.setting-value.editable:not([data-setting="email"])');
  editableFields.forEach(field => {
    const displayValue = field.querySelector('.display-value');
    const input = field.querySelector('.edit-input');
    displayValue.addEventListener('click', () => {
      displayValue.classList.add('hidden');
      input.classList.remove('hidden');
      input.focus();
    });
    input.addEventListener('blur', async () => {
      const newValue = input.value.trim();
      const setting = field.dataset.setting;
      try {
        const response = await fetch('/api/settings/update', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'CSRF-Token': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
          },
          body: JSON.stringify({ setting, value: newValue })
        });
        if (response.ok) {
          displayValue.textContent = newValue || 'Not set';
          input.classList.add('hidden');
          displayValue.classList.remove('hidden');
        } else {
          throw new Error('Failed to update setting');
        }
      } catch (error) {
        console.error('Error updating setting:', error);
        input.value = displayValue.textContent;
        input.classList.add('hidden');
        displayValue.classList.remove('hidden');
      }
    });
    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        input.blur();
      }
    });
  });

  // Toggle switches update functionality
  const toggleSwitches = document.querySelectorAll('.setting-value.toggleable input[type="checkbox"]');
  toggleSwitches.forEach(toggle => {
    toggle.addEventListener('change', async () => {
      const setting = toggle.closest('.setting-value').dataset.setting;
      const value = toggle.checked;
      try {
        const response = await fetch('/api/settings/update', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'CSRF-Token': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
          },
          body: JSON.stringify({ setting, value })
        });
        if (!response.ok) {
          throw new Error('Failed to update setting');
        }
      } catch (error) {
        console.error('Error updating setting:', error);
        toggle.checked = !value;
      }
    });
  });
});
