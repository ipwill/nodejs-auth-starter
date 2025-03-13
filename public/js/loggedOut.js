/**
 * @fileoverview Simple log out functionality
 * @version 1.3
 * @lastModified 2025-03-13 13:47:04 UTC
 * @author cgtwig
 */

document.addEventListener('DOMContentLoaded', () => {
    const loginRedirectButton = document.getElementById('login-redirect-button');
    
    if (loginRedirectButton) {
        loginRedirectButton.addEventListener('click', () => {
            window.location.href = '/';
        });
    }
    
    console.log('Session ended at ' + new Date().toISOString());
});
