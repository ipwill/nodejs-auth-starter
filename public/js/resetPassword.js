import { toggleSpinner, showModal, validatePassword } from './script.js';

document.addEventListener('DOMContentLoaded', () => {
    const passwordInput = document.getElementById('password');
    const form = document.getElementById('reset-password');

    passwordInput.addEventListener('input', () => {
        validatePassword(passwordInput.value);
    });

    form.addEventListener('submit', async e => {
        e.preventDefault();
        const formData = new FormData(form);
        const data = {};
        formData.forEach((value, key) => { data[key] = value; });
        if (!validatePassword(data.password)) {
            document.getElementById('reset-password-error').textContent = 'Password does not meet the requirements.';
            return;
        }
        toggleSpinner(true, 'reset-password-button');
        try {
            const response = await fetch('/api/reset-password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').getAttribute('content')
                },
                body: JSON.stringify(data)
            });
            if (response.ok) {
                alert('Password reset successful. Please log in with your new password.');
                window.location.href = '/';
            } else {
                const result = await response.json();
                document.getElementById('reset-password-error').textContent = result.message;
            }
        } catch (err) {
            document.getElementById('reset-password-error').textContent = 'An error occurred.';
        } finally {
            toggleSpinner(false, 'reset-password-button');
        }
    });
});
