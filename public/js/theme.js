(function() {
  try {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    console.log(`Theme initialized to: ${savedTheme}`);
  } catch (e) {
    console.error('Error applying initial theme:', e);
  }
})();

document.addEventListener('DOMContentLoaded', function() {
  const themeToggle = document.getElementById('theme-toggle');
  
  if (themeToggle) {
    themeToggle.addEventListener('click', function() {
      try {
        const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
        const newTheme = currentTheme === 'light' ? 'dark' : 'light';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);

        const now = new Date();
        const formattedTime = formatDateTime(now);
        console.log(`Theme changed to ${newTheme} at ${formattedTime}`);
      } catch (e) {
        console.error('Error toggling theme:', e);
      }
    });
    console.log('Theme toggle handler initialized');
  } else {
    console.error('Theme toggle button not found in DOM');
  }
  
  function formatDateTime(date) {
    return date.getUTCFullYear() + '-' + 
           String(date.getUTCMonth() + 1).padStart(2, '0') + '-' + 
           String(date.getUTCDate()).padStart(2, '0') + ' ' + 
           String(date.getUTCHours()).padStart(2, '0') + ':' + 
           String(date.getUTCMinutes()).padStart(2, '0') + ':' + 
           String(date.getUTCSeconds()).padStart(2, '0');
  }
});
