document.addEventListener('DOMContentLoaded', function () {
  const logoutButton = document.getElementById('logout-button');
  const dashboardSection = document.getElementById('dashboard-section');
  const settingsSection = document.getElementById('settings-section');
  const saveButtons = document.querySelectorAll('.save-button');
  
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

  const editableFields = document.querySelectorAll('.setting-value.editable');
  editableFields.forEach(field => {
    const displayValue = field.querySelector('.display-value');
    const input = field.querySelector('.edit-input');
    const saveButton = field.querySelector('.save-button');
    
    field.addEventListener('click', () => {
      displayValue.classList.add('hidden');
      input.classList.remove('hidden');
      input.focus();
      saveButton.classList.remove('hidden');
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
          saveButton.classList.add('hidden');
          showSuccessMessage(setting);
        } else {
          const result = await response.json();
          throw new Error(result.message);
        }
      } catch (error) {
        console.error('Error updating setting:', error);
        input.value = displayValue.textContent;
        input.classList.add('hidden');
        displayValue.classList.remove('hidden');
        saveButton.classList.add('hidden');
        showErrorMessage(error.message);
      }
    });

    input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        input.blur();
      }
    });
  });

  saveButtons.forEach(button => {
    button.addEventListener('click', async function () {
      const parent = button.closest('.setting-value.editable');
      const input = parent.querySelector('.edit-input');
      const displayValue = parent.querySelector('.display-value');
      const newValue = input.value.trim();
      const setting = parent.getAttribute('data-setting');

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
          displayValue.textContent = newValue;
          input.classList.add('hidden');
          button.classList.add('hidden');
          displayValue.classList.remove('hidden');
          showSuccessMessage(setting);
        } else {
          const result = await response.json();
          throw new Error(result.message);
        }
      } catch (error) {
        console.error('Error updating setting:', error);
        input.classList.add('hidden');
        button.classList.add('hidden');
        displayValue.classList.remove('hidden');
        showErrorMessage(error.message);
      }
    });
  });

  function showSuccessMessage(setting) {
    const successMessage = document.createElement('div');
    successMessage.textContent = `${setting} updated successfully!`;
    successMessage.classList.add('success-message');
    document.body.appendChild(successMessage);
    setTimeout(() => {
      successMessage.remove();
    }, 3000);
  }

  function showErrorMessage(message) {
    const errorMessage = document.createElement('div');
    errorMessage.textContent = message;
    errorMessage.classList.add('error-message');
    document.body.appendChild(errorMessage);
    setTimeout(() => {
      errorMessage.remove();
    }, 3000);
  }
});
