// CSRF Bank - Client-side functionality
document.addEventListener('DOMContentLoaded', function() {
  // Auto-dismiss alerts after 5 seconds
  document.querySelectorAll('.alert').forEach(function(alert) {
    setTimeout(function() {
      alert.style.opacity = '0';
      alert.style.transition = 'opacity 0.3s';
      setTimeout(function() { alert.remove(); }, 300);
    }, 5000);
  });
});
