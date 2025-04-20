import { toggleSpinner, showModal, validatePassword } from './script.js';

class PasswordResetManager {
    constructor() {
        this.form = document.getElementById('reset-password');
        this.passwordInput = document.getElementById('password');
        this.errorDisplay = document.getElementById('reset-password-error');
        this.csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        
        this.init();
    }

    init() {
        if (!this.form || !this.passwordInput || !this.errorDisplay) {
            console.error('Required elements not found');
            return;
        }

        this.setupEventListeners();
    }

    setupEventListeners() {
        this.passwordInput.addEventListener('input', () => {
            this.validatePasswordInput();
        });

        this.form.addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.handleFormSubmit();
        });
    }

    validatePasswordInput() {
        validatePassword(this.passwordInput.value);
    }

    showError(message) {
        if (this.errorDisplay) {
            this.errorDisplay.textContent = message;
        }
    }

    getFormData() {
        const formData = new FormData(this.form);
        const data = {};
        formData.forEach((value, key) => { 
            data[key] = value;
        });
        return data;
    }

    async handleFormSubmit() {
        const data = this.getFormData();

        if (!validatePassword(data.password)) {
            this.showError('Password does not meet the requirements.');
            return;
        }

        toggleSpinner(true, 'reset-password-button');

        try {
            const response = await this.submitPasswordReset(data);
            await this.handleResponse(response);
        } catch (error) {
            this.showError('An error occurred while resetting the password.');
            console.error('Password reset error:', error);
        } finally {
            toggleSpinner(false, 'reset-password-button');
        }
    }

    async submitPasswordReset(data) {
        if (!this.csrfToken) {
            throw new Error('CSRF token not found');
        }

        return await fetch('/api/reset-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': this.csrfToken
            },
            body: JSON.stringify(data)
        });
    }

    async handleResponse(response) {
        if (response.ok) {
            showModal('Password reset successful. Please log in with your new password.');
            window.location.href = '/';
        } else {
            const result = await response.json();
            this.showError(result.message || 'Password reset failed.');
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    new PasswordResetManager();
});
