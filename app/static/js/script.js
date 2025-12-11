// Custom JavaScript for ЗЭДКД
document.addEventListener('DOMContentLoaded', function() {
    // Add any custom JavaScript here
    console.log('ЗЭДКД application loaded');
    
    // Example: Confirm delete actions
    const deleteButtons = document.querySelectorAll('.delete-btn');
    deleteButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            const confirmed = confirm('Are you sure you want to delete this item?');
            if (!confirmed) {
                e.preventDefault();
            }
        });
    });
});