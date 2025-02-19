/**
 * @fileoverview Common utility functions for the application
 * @version 1.2
 * @lastModified 2025-02-19 16:26:26 UTC
 * @author cgtwig
 */

/**
 * Creates and displays a modal with a message and close button
 * @param {string} message - The message to display in the modal
 */
function showModal(message) {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-overlay">
            <div class="modal-content">
                <p>${message}</p>
                <button id="close-modal">Close</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    document.getElementById('close-modal').addEventListener('click', () => modal.remove());
}

/**
 * Toggles the visibility of loading spinners
 * @param {boolean} visible - Whether the spinner should be visible
 * @param {string|null} buttonId - Optional ID of button containing spinner
 */
function toggleSpinner(visible, buttonId = null) {
    if (buttonId) {
        const button = document.getElementById(buttonId);
        if (button) {
            const buttonContent = button.querySelector('.button-content');
            const buttonSpinner = button.querySelector('.button-spinner');
            button.disabled = visible;
            buttonContent.classList.toggle('hidden', visible);
            buttonSpinner.classList.toggle('hidden', !visible);
        }
    }
    const spinner = document.getElementById('loading-spinner');
    if (spinner) {
        spinner.style.display = visible ? 'block' : 'none';
    }
}

/**
 * Validates password against security requirements
 * @param {string} password - The password to validate
 * @returns {boolean} - Whether the password meets all requirements
 */
function validatePassword(password) {
    const requirements = {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        special: /[@$!%*?&]/.test(password)
    };

    Object.entries(requirements).forEach(([key, isValid]) => {
        const element = document.getElementById(key);
        if (element) {
            element.classList.toggle('valid', isValid);
            element.classList.toggle('invalid', !isValid);
        }
    });

    return Object.values(requirements).every(Boolean);
}

export { showModal, toggleSpinner, validatePassword };
