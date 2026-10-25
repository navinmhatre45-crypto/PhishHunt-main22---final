// Modal Functions
function showSignIn() {
    document.getElementById('signInModal').style.display = 'block';
}

function showGetStarted() {
    document.getElementById('getStartedModal').style.display = 'block';
}

function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modals = document.getElementsByClassName('modal');
    for (let modal of modals) {
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    }
}

// Notification function
function showNotification(message, type = 'info') {
    // Remove existing notifications
    const existingNotifications = document.querySelectorAll('.notification');
    existingNotifications.forEach(notification => notification.remove());
    
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <span>${message}</span>
        <button onclick="this.parentElement.remove()">&times;</button>
    `;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
}

// History filtering functionality
function filterHistory(type) {
    console.log('Filtering history by:', type);
    const historyItems = document.querySelectorAll('.history-item');
    let visibleCount = 0;
    
    historyItems.forEach(item => {
        const isPhishing = item.querySelector('.phishing-badge');
        const isSafe = item.querySelector('.safe-badge');
        
        if (type === 'all') {
            item.style.display = 'flex';
            visibleCount++;
        } else if (type === 'phishing' && isPhishing) {
            item.style.display = 'flex';
            visibleCount++;
        } else if (type === 'safe' && isSafe) {
            item.style.display = 'flex';
            visibleCount++;
        } else {
            item.style.display = 'none';
        }
    });
    
    // Update stats display
    updateFilterStats(type, visibleCount);
}

function updateFilterStats(type, count) {
    const statsText = document.querySelector('.filter-stats');
    if (statsText) {
        if (type === 'all') {
            statsText.textContent = `Showing all ${count} checks`;
        } else if (type === 'phishing') {
            statsText.textContent = `Showing ${count} phishing URLs`;
        } else if (type === 'safe') {
            statsText.textContent = `Showing ${count} safe URLs`;
        }
    }
}

function updateHistoryStats() {
    const totalItems = document.querySelectorAll('.history-item:not([style*="display: none"])').length;
    const phishingItems = document.querySelectorAll('.phishing-badge').length;
    const safeItems = document.querySelectorAll('.safe-badge').length;
    
    const totalElement = document.querySelector('.total-checks');
    const phishingElement = document.querySelector('.phishing-detected');
    const safeElement = document.querySelector('.safe-urls');
    
    if (totalElement) totalElement.textContent = totalItems;
    if (phishingElement) phishingElement.textContent = phishingItems;
    if (safeElement) safeElement.textContent = safeItems;
}

// History actions functions
function recheckUrl(url) {
    if (!url) {
        console.error('No URL provided for recheck');
        return;
    }
    
    console.log('Rechecking URL:', url);
    showNotification('Rechecking URL...', 'info');
    
    // Create and submit form
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/check';
    
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = 'url';
    input.value = url;
    
    form.appendChild(input);
    document.body.appendChild(form);
    form.submit();
}

function shareResult(url, isPhishing) {
    if (!url) {
        console.error('No URL provided for sharing');
        return;
    }
    
    console.log('Sharing result for URL:', url, 'Is phishing:', isPhishing);
    const resultText = isPhishing ? '🚫 Phishing URL Detected' : '✅ Safe URL';
    const shareText = `${resultText}: ${url}\n\nChecked with PhishHunt - Stay safe online!`;
    
    // Try Web Share API first
    if (navigator.share) {
        navigator.share({
            title: 'PhishHunt URL Check Result',
            text: shareText,
            url: window.location.href
        }).then(() => {
            showNotification('Result shared successfully!', 'success');
        }).catch((error) => {
            console.log('Web Share failed, falling back to clipboard:', error);
            copyToClipboard(shareText);
        });
    } else {
        copyToClipboard(shareText);
    }
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showNotification('Result copied to clipboard!', 'success');
    }).catch((error) => {
        console.log('Clipboard API failed, using fallback:', error);
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            showNotification('Result copied to clipboard!', 'success');
        } catch (err) {
            console.error('Fallback copy failed:', err);
            showNotification('Failed to copy result', 'error');
        }
        document.body.removeChild(textArea);
    });
}

function deleteCheck(checkId) {
    if (!checkId) {
        console.error('No check ID provided for deletion');
        return;
    }
    
    if (!confirm('Are you sure you want to delete this check record?')) {
        return;
    }
    
    console.log('Deleting check:', checkId);
    
    // Show loading state
    const deleteBtn = document.querySelector(`[data-check-id="${checkId}"]`);
    if (deleteBtn) {
        deleteBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        deleteBtn.disabled = true;
    }
    
    // Send DELETE request
    fetch(`/delete_check/${checkId}`, {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
        }
    }).then(response => {
        if (response.ok) {
            showNotification('Check record deleted successfully!', 'success');
            const item = document.querySelector(`[data-check-id="${checkId}"]`)?.closest('.history-item');
            if (item) {
                // Add removing class for animation
                item.classList.add('removing');
                
                // Remove after animation
                setTimeout(() => {
                    item.remove();
                    updateHistoryStats();
                    
                    // Show empty state if no items left
                    const historyList = document.querySelector('.history-list');
                    const remainingItems = historyList.querySelectorAll('.history-item').length;
                    if (remainingItems === 0) {
                        historyList.innerHTML = `
                            <div class="empty-state">
                                <i class="fas fa-history"></i>
                                <h3>No check history</h3>
                                <p>Your URL check history will appear here</p>
                                <a href="/" class="btn btn-primary" style="margin-top: 20px;">
                                    <i class="fas fa-plus"></i> Check Your First URL
                                </a>
                            </div>
                        `;
                    }
                }, 300);
            } else {
                // Fallback: reload page
                location.reload();
            }
        } else {
            throw new Error('Delete failed');
        }
    }).catch(error => {
        console.error('Error deleting check:', error);
        showNotification('Failed to delete check record', 'error');
        
        // Reset button state
        if (deleteBtn) {
            deleteBtn.innerHTML = '<i class="fas fa-trash"></i>';
            deleteBtn.disabled = false;
        }
    });
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    console.log('Initializing history page functionality...');
    
    // Initialize history stats
    updateHistoryStats();
    
    // Filter buttons event listeners
    document.querySelectorAll('.filter-btn').forEach(button => {
        button.addEventListener('click', function() {
            const filterType = this.dataset.filter;
            console.log('Filter button clicked:', filterType);
            filterHistory(filterType);
            
            // Update active state
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            this.classList.add('active');
        });
    });
    
    // Stat cards event listeners (for filtering)
    document.querySelectorAll('.stat-card').forEach(card => {
        card.addEventListener('click', function() {
            const filterType = this.classList.contains('phishing') ? 'phishing' : 
                             this.classList.contains('safe') ? 'safe' : 'all';
            console.log('Stat card clicked, filtering:', filterType);
            filterHistory(filterType);
            
            // Update filter buttons active state
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
                if (btn.dataset.filter === filterType) {
                    btn.classList.add('active');
                }
            });
        });
    });
    
    // Remove any previous event delegation for history actions and add a robust one:
    document.addEventListener('DOMContentLoaded', function() {
        const historyList = document.querySelector('.history-list');
        if (historyList) {
            historyList.addEventListener('click', function(e) {
                const target = e.target;

                // Recheck button
                const recheckBtn = target.closest('.recheck-btn');
                if (recheckBtn) {
                    e.preventDefault();
                    e.stopPropagation();
                    const url = recheckBtn.dataset.url;
                    if (url) {
                        // Always POST to /check_url to show result page directly
                        const form = document.createElement('form');
                        form.method = 'POST';
                        form.action = '/check_url';
                        form.style.display = 'none';

                        const input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = 'url';
                        input.value = url;
                        form.appendChild(input);

                        document.body.appendChild(form);
                        form.submit();
                    }
                    return;
                }

                // Delete button
                const deleteBtn = target.closest('.delete-check-btn');
                if (deleteBtn) {
                    e.preventDefault();
                    e.stopPropagation();
                    const checkId = deleteBtn.dataset.checkId;
                    if (checkId && confirm('Are you sure you want to delete this check record?')) {
                        fetch(`/delete_check/${checkId}`, {
                            method: 'DELETE',
                            headers: {
                                'Content-Type': 'application/json',
                            }
                        }).then(response => {
                            if (response.ok) {
                                showNotification('Check record deleted successfully!', 'success');
                                const item = deleteBtn.closest('.history-item');
                                if (item) {
                                    item.classList.add('removing');
                                    setTimeout(() => {
                                        item.remove();
                                        // Optionally update stats or show empty state
                                        const historyList = document.querySelector('.history-list');
                                        if (historyList && !historyList.querySelector('.history-item')) {
                                            historyList.innerHTML = `
                                                <div class="empty-state">
                                                    <i class="fas fa-history"></i>
                                                    <h3>No check history yet</h3>
                                                    <p>Start by checking some URLs to see your history here.</p>
                                                    <a href="/" class="btn btn-primary">Check a URL</a>
                                                </div>
                                            `;
                                        }
                                    }, 300);
                                } else {
                                    location.reload();
                                }
                            } else {
                                showNotification('Failed to delete check record', 'error');
                            }
                        }).catch(() => {
                            showNotification('Failed to delete check record', 'error');
                        });
                    }
                    return;
                }

                // Share button (leave as-is)
                const shareBtn = target.closest('.share-btn');
                if (shareBtn) {
                    e.preventDefault();
                    e.stopPropagation();
                    const url = shareBtn.dataset.url;
                    const isPhishing = shareBtn.dataset.isPhishing === 'true';
                    if (url) {
                        const resultText = isPhishing ? '🚫 Phishing URL Detected' : '✅ Safe URL';
                        const shareText = `${resultText}: ${url}\n\nChecked with PhishHunt - Stay safe online!`;
                        if (navigator.share) {
                            navigator.share({
                                title: 'PhishHunt URL Check Result',
                                text: shareText,
                                url: window.location.href
                            }).then(() => {
                                showNotification('Result shared successfully!', 'success');
                            }).catch(() => {
                                copyToClipboard(shareText);
                            });
                        } else {
                            copyToClipboard(shareText);
                        }
                    }
                    return;
                }
            });
        }
    });
});
