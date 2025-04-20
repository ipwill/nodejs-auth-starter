document.addEventListener('DOMContentLoaded', () => {
    const loginRedirectButton = document.getElementById('login-redirect-button');
    
    if (loginRedirectButton) {
        loginRedirectButton.addEventListener('click', () => {
            window.location.href = '/';
        });
    }
    
    console.log('Session ended at ' + new Date().toISOString());
});
