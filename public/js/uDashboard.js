document.addEventListener('DOMContentLoaded', () => {
    class DashboardManager {
        constructor() {
            this.csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
            this.setupEditButtons();
            this.setupLogout();
            this.checkAuth();
        }
        async checkAuth() {
            try {
                const response = await fetch('/api/check-auth', { method: 'GET', credentials: 'same-origin' });
                if (!response.ok) throw new Error('Authentication failed');
            } catch (e) {
                this.handleLogout();
            }
        }
        handleLogout() {
            localStorage.clear();
            sessionStorage.clear();
            window.location.href = '/logged-out';
        }
        setupLogout() {
            const logoutButton = document.getElementById('logout-button');
            if (logoutButton) {
                logoutButton.addEventListener('click', async () => {
                    try {
                        await fetch('/api/logout', {
                            method: 'POST',
                            credentials: 'same-origin',
                            headers: { 'CSRF-Token': this.csrfToken }
                        });
                    } catch (e) {
                        console.error('Logout failed', e);
                    } finally {
                        this.handleLogout();
                    }
                });
            }
        }
        setupEditButtons() {
            const editButtons = document.querySelectorAll('.edit-button');
            editButtons.forEach(button => {
                button.addEventListener('click', () => {
                    const setting = button.dataset.setting;
                    const row = document.querySelector(`tr[data-setting="${setting}"]`);
                    if (!row) return;
                    const displayValue = row.querySelector('.display-value');
                    const inputs = row.querySelectorAll('.edit-input');
                    displayValue.classList.add('hidden');
                    inputs.forEach(input => {
                        input.classList.remove('hidden');
                        input.focus();
                        input.addEventListener('keypress', (e) => {
                            if (e.key === 'Enter') input.blur();
                        });
                        input.addEventListener('blur', () => {
                            this.updateSetting(setting, Array.from(inputs).map(i => i.value.trim()));
                        });
                    });
                });
            });
        }
        async updateSetting(setting, values) {
            let payload = { setting, value: '' };
            if (setting === 'password') {
                if (values[0] !== values[1]) {
                    this.showMessage('Passwords do not match', 'error');
                    return;
                }
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
                        'CSRF-Token': this.csrfToken
                    },
                    body: JSON.stringify(payload)
                });
                if (!response.ok) {
                    const result = await response.json();
                    throw new Error(result.message || 'Update failed');
                }
                this.showMessage(`${setting} updated successfully`, 'success');
                const row = document.querySelector(`tr[data-setting="${setting}"]`);
                if (setting !== 'password') {
                    row.querySelector('.display-value').textContent = payload.value || 'Not set';
                }
                row.querySelectorAll('.edit-input').forEach(input => input.classList.add('hidden'));
                row.querySelector('.display-value').classList.remove('hidden');
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
}); 
