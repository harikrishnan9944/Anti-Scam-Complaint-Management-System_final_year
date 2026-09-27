/**
 * Smart Anti-Scam Complaint Management System - Client Javascript
 */

document.addEventListener('DOMContentLoaded', function () {
    // Auto-dismiss bootstrap alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) {
                bsAlert.close();
            }
        }, 5000);
    });

    // Confirmation modal or alert on key forms
    const confirmForms = document.querySelectorAll('[data-confirm]');
    confirmForms.forEach(function (form) {
        form.addEventListener('submit', function (e) {
            const msg = form.getAttribute('data-confirm') || 'Are you sure you want to proceed?';
            if (!confirm(msg)) {
                e.preventDefault();
            }
        });
    });

    // Real-time table search filter
    const searchInputs = document.querySelectorAll('[data-table-search]');
    searchInputs.forEach(function (input) {
        const targetTableId = input.getAttribute('data-table-search');
        const targetTable = document.getElementById(targetTableId);
        
        if (targetTable) {
            input.addEventListener('keyup', function () {
                const term = input.value.toLowerCase().trim();
                const rows = targetTable.querySelectorAll('tbody tr');
                
                rows.forEach(function (row) {
                    const text = row.textContent.toLowerCase();
                    if (text.indexOf(term) > -1) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                });
            });
        }
    });
});
