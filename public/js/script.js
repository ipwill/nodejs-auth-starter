function showModal(message) {
  const modal = document.createElement('div');
  modal.className = 'modal';
  modal.innerHTML = `
    <div class="modal-content">
      <p>${message}</p>
      <button id="close-modal">Close</button>
    </div>
  `;
  document.body.appendChild(modal);
  document.getElementById('close-modal').onclick = () => modal.remove();
}

function toggleSpinner(visible, buttonId = null) {
  if (buttonId) {
    const button = document.getElementById(buttonId);
    if (button) {
      const buttonContent = button.querySelector('.button-content');
      const buttonSpinner = button.querySelector('.button-spinner');
      
      if (visible) {
        button.disabled = true;
        buttonContent.classList.add('hidden');
        buttonSpinner.classList.remove('hidden');
      } else {
        button.disabled = false;
        buttonContent.classList.remove('hidden');
        buttonSpinner.classList.add('hidden');
      }
    }
  }
  
  // Main spinner toggle (for backwards compatibility)
  const spinner = document.getElementById('loading-spinner');
  if (spinner) spinner.style.display = visible ? 'block' : 'none';
}

export { showModal, toggleSpinner };