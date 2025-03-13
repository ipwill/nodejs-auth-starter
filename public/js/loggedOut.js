/**
 * @fileoverview Simple log out functionality
 * @version 1.2
 * @lastModified 2025-03-13 04:16:27 UTC
 * @author cgtwig
 */

document.addEventListener('DOMContentLoaded', () => {
    const themeToggle = document.getElementById('theme-toggle');
    const loginRedirectButton = document.getElementById('login-redirect-button');
    
    if (themeToggle) {
        const htmlElement = document.documentElement;
        const savedTheme = localStorage.getItem('theme') || 'light';
        htmlElement.setAttribute('data-theme', savedTheme);
        
        themeToggle.addEventListener('click', () => {
            const currentTheme = htmlElement.getAttribute('data-theme');
            const newTheme = currentTheme === 'light' ? 'dark' : 'light';
            
            htmlElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        });
    }
    
    if (loginRedirectButton) {
        loginRedirectButton.addEventListener('click', () => {
            window.location.href = '/';
        });
    }
});
