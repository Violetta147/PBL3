/**
 * Search UI Module
 * UI interactions and enhancements for search functionality
 * Phase 2: Basic UI enhancements without location services
 */
var SearchUI = (function() {
    'use strict';

    // Private variables
    var searchForm = null;
    var searchInput = null;
    var locationInput = null;
    var searchButton = null;
    var clearButton = null;
    var historyContainer = null;

    // Configuration
    var config = {
        animationDuration: 300,
        debounceDelay: 300,
        maxHistoryItems: 5
    };

    // Initialize UI enhancements
    function init() {
        cacheDOM();
        setupEnhancements();
        bindEvents();
        createClearButton();
        setupSearchHistory();
    }

    // Cache DOM elements
    function cacheDOM() {
        searchForm = document.getElementById('navbarSearchForm');
        searchInput = searchForm ? searchForm.querySelector('input[name="searchTerm"]') : null;
        locationInput = document.getElementById('navbarLocationInput');
        searchButton = searchForm ? searchForm.querySelector('button[type="submit"]') : null;
    }

    // Setup UI enhancements
    function setupEnhancements() {
        if (!searchForm) return;

        // Add CSS classes for enhanced styling
        searchForm.classList.add('search-enhanced');
        
        // Add placeholder animations
        setupPlaceholderAnimation();
        
        // Add focus effects
        setupFocusEffects();
        
        // Add loading indicators
        setupLoadingIndicators();
    }

    // Bind UI event listeners
    function bindEvents() {
        if (!searchForm) return;

        // Input focus/blur effects
        if (searchInput) {
            searchInput.addEventListener('focus', handleInputFocus);
            searchInput.addEventListener('blur', handleInputBlur);
            searchInput.addEventListener('input', handleInputChange);
        }

        if (locationInput) {
            locationInput.addEventListener('focus', handleInputFocus);
            locationInput.addEventListener('blur', handleInputBlur);
            locationInput.addEventListener('input', handleInputChange);
        }

        // Form submission effects
        searchForm.addEventListener('submit', handleFormSubmit);

        // Keyboard shortcuts
        document.addEventListener('keydown', handleKeyboardShortcuts);
    }    // Setup placeholder (no animation)
    function setupPlaceholderAnimation() {
        // No animations - do nothing
        return;
    }    // Setup focus effects (with no animations)
    function setupFocusEffects() {
        var style = document.createElement('style');
        style.textContent = `
            .search-enhanced .fishloot-search-input:focus,
            .search-enhanced .fishloot-search-location:focus {
                border-color: #25A18E;
                box-shadow: 0 0 0 2px rgba(37, 161, 142, 0.2);
                outline: none;
            }
            
            .search-enhanced .fishloot-search-button:hover {
                background-color: #1e8b7a;
            }
            
            .search-clear-button {
                position: absolute;
                right: 8px;
                top: 50%;
                transform: translateY(-50%);
                background: none;
                border: none;
                color: #666;
                cursor: pointer;
                font-size: 14px;
                padding: 4px;
                border-radius: 50%;
                opacity: 1;
            }
            
            .search-clear-button:hover {
                background-color: #f0f0f0;
                color: #333;
            }
            
            .search-history {
                position: absolute;
                top: 100%;
                left: 0;
                right: 0;
                background: white;
                border: 1px solid #7AE582;
                border-top: none;
                max-height: 200px;
                overflow-y: auto;
                z-index: 1000;
                display: none;
            }
            
            .search-history.show {
                display: block;
            }
            
            .search-history-item {
                padding: 8px 16px;
                cursor: pointer;
                border-bottom: 1px solid #f0f0f0;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .search-history-item:hover {
                background-color: #f8f9fa;
            }
            
            .search-history-item:last-child {
                border-bottom: none;
            }
            
            .search-history-text {
                flex: 1;
                font-size: 14px;
            }
            
            .search-history-time {
                font-size: 12px;
                color: #666;
                margin-left: 8px;
            }
            
            .search-history-delete {
                background: none;
                border: none;
                color: #999;
                cursor: pointer;
                padding: 2px;
                margin-left: 8px;
            }
            
            .search-history-delete:hover {
                color: #dc3545;
            }
        `;
        document.head.appendChild(style);
    }

    // Setup loading indicators
    function setupLoadingIndicators() {
        // This will be used by SearchCore when form is submitted
    }

    // Handle input focus
    function handleInputFocus(event) {
        var input = event.target;
        input.parentElement.classList.add('focused');
        
        // Show search history for search input
        if (input === searchInput) {
            showSearchHistory();
        }
    }

    // Handle input blur
    function handleInputBlur(event) {
        var input = event.target;
        setTimeout(function() {
            input.parentElement.classList.remove('focused');
            hideSearchHistory();
        }, 200);
    }

    // Handle input change
    function handleInputChange(event) {
        var input = event.target;
        updateClearButton(input);
        
        // Real-time validation feedback
        if (typeof SearchValidation !== 'undefined') {
            clearValidationStyles(input);
        }
    }    // Handle form submission
    function handleFormSubmit(event) {
        // No submission animation
        
        // Hide any open dropdowns
        hideSearchHistory();
        var locationSuggestion = document.getElementById('location-suggestion');
        if (locationSuggestion) {
            locationSuggestion.classList.remove('show');
        }
    }

    // Handle keyboard shortcuts
    function handleKeyboardShortcuts(event) {
        // Ctrl/Cmd + K to focus search
        if ((event.ctrlKey || event.metaKey) && event.key === 'k') {
            event.preventDefault();
            if (searchInput) {
                searchInput.focus();
                searchInput.select();
            }
        }
          // Escape to clear focus and close dropdowns
        if (event.key === 'Escape') {
            if (searchInput) searchInput.blur();
            if (locationInput) locationInput.blur();
            hideSearchHistory();
            var locationSuggestion = document.getElementById('location-suggestion');
            if (locationSuggestion) {
                locationSuggestion.classList.remove('show');
            }
        }
    }

    // Create clear button for inputs
    function createClearButton() {
        [searchInput, locationInput].forEach(function(input) {
            if (!input) return;
            
            var container = input.parentElement;
            if (container.style.position !== 'relative') {
                container.style.position = 'relative';
            }
            
            var clearBtn = document.createElement('button');
            clearBtn.type = 'button';
            clearBtn.className = 'search-clear-button';
            clearBtn.innerHTML = '<i class="fas fa-times"></i>';
            clearBtn.title = 'Clear';
            
            clearBtn.addEventListener('click', function() {
                input.value = '';
                input.focus();
                updateClearButton(input);
                input.dispatchEvent(new Event('input'));
            });
            
            container.appendChild(clearBtn);
            
            // Show/hide based on input content
            updateClearButton(input);
        });
    }

    // Update clear button visibility
    function updateClearButton(input) {
        if (!input) return;
        
        var clearBtn = input.parentElement.querySelector('.search-clear-button');
        if (clearBtn) {
            if (input.value.trim()) {
                clearBtn.classList.add('show');
            } else {
                clearBtn.classList.remove('show');
            }
        }
    }

    // Setup search history functionality
    function setupSearchHistory() {
        if (!searchInput) return;
        
        // Create history container
        var container = searchInput.parentElement;
        if (container.style.position !== 'relative') {
            container.style.position = 'relative';
        }
        
        historyContainer = document.createElement('div');
        historyContainer.className = 'search-history';
        historyContainer.id = 'search-history';
        
        container.appendChild(historyContainer);
    }

    // Show search history
    function showSearchHistory() {
        if (!historyContainer || typeof SearchStorage === 'undefined') return;
        
        var history = SearchStorage.getHistory();
        if (!history || history.length === 0) return;
        
        historyContainer.innerHTML = '';
        
        history.slice(0, config.maxHistoryItems).forEach(function(item, index) {
            var historyItem = document.createElement('div');
            historyItem.className = 'search-history-item';
            
            var text = item.searchTerm || item.location || 'Unknown search';
            var time = formatRelativeTime(new Date(item.timestamp));
            
            historyItem.innerHTML = `
                <span class="search-history-text">${escapeHtml(text)}</span>
                <span class="search-history-time">${time}</span>
                <button type="button" class="search-history-delete" data-index="${index}">
                    <i class="fas fa-times"></i>
                </button>
            `;
            
            // Click to use this search
            historyItem.addEventListener('click', function(e) {
                if (e.target.closest('.search-history-delete')) {
                    SearchStorage.removeFromHistory(index);
                    showSearchHistory(); // Refresh
                    return;
                }
                
                if (searchInput && item.searchTerm) {
                    searchInput.value = item.searchTerm;
                }
                if (locationInput && item.location) {
                    locationInput.value = item.location;
                }
                
                hideSearchHistory();
                updateClearButton(searchInput);
                updateClearButton(locationInput);
            });
            
            historyContainer.appendChild(historyItem);
        });
        
        historyContainer.classList.add('show');
    }

    // Hide search history
    function hideSearchHistory() {
        if (historyContainer) {
            historyContainer.classList.remove('show');
        }
    }

    // Clear validation styles
    function clearValidationStyles(input) {
        input.style.borderColor = '';
        input.style.backgroundColor = '';
    }

    // Format relative time
    function formatRelativeTime(date) {
        var now = new Date();
        var diffMs = now - date;
        var diffMins = Math.floor(diffMs / 60000);
        var diffHours = Math.floor(diffMs / 3600000);
        var diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) return 'Vừa xong';
        if (diffMins < 60) return diffMins + ' phút trước';
        if (diffHours < 24) return diffHours + ' giờ trước';
        if (diffDays < 7) return diffDays + ' ngày trước';
        
        return date.toLocaleDateString('vi-VN');
    }

    // Escape HTML to prevent XSS
    function escapeHtml(text) {
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Public API
    return {
        init: init,
        showSearchHistory: showSearchHistory,
        hideSearchHistory: hideSearchHistory,
        updateClearButton: updateClearButton
    };
})();

// Price filter button functionality
document.addEventListener('DOMContentLoaded', function() {
    // Handle price filter buttons
    const priceButtons = document.querySelectorAll('.price-filter .btn');
    priceButtons.forEach(button => {
        button.addEventListener('click', function() {
            // Toggle active state
            this.classList.toggle('active');
            
            // Get selected price levels
            const selectedPrices = Array.from(document.querySelectorAll('.price-filter .btn.active'))
                .map(btn => btn.textContent.trim());
            
            console.log('Selected price levels:', selectedPrices);
            // You can add logic here to filter restaurants by price
        });
    });
    
    // Handle "See all" buttons for expandable sections
    const seeAllButtons = document.querySelectorAll('.btn-link');
    seeAllButtons.forEach(button => {
        if (button.textContent.includes('Xem tất cả')) {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                
                // Find the parent filter section
                const filterSection = this.closest('.filter-section');
                const hiddenItems = filterSection.querySelectorAll('.form-check:nth-child(n+7)');
                
                if (hiddenItems.length > 0) {
                    // Show hidden items
                    hiddenItems.forEach(item => {
                        item.style.display = 'block';
                    });
                    this.textContent = 'Thu gọn';
                } else {
                    // Hide items beyond the first 6
                    const allItems = filterSection.querySelectorAll('.form-check');
                    for (let i = 6; i < allItems.length; i++) {
                        allItems[i].style.display = 'none';
                    }
                    this.textContent = 'Xem tất cả';
                }
            });
        }
    });
    
    // Handle distance filter changes
    const distanceRadios = document.querySelectorAll('input[name="distance"]');
    distanceRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            console.log('Distance filter changed to:', this.value);
            // You can add logic here to update the search with distance filter
        });
    });
    
    // Handle suggestion filters
    const suggestionCheckboxes = document.querySelectorAll('.suggested-filters input[type="checkbox"]');
    suggestionCheckboxes.forEach(checkbox => {
        checkbox.addEventListener('change', function() {
            console.log('Suggestion filter changed:', this.id, this.checked);
            // You can add logic here to handle suggestion filters
        });
    });
});

// Function to update URL with current filter state
function updateFiltersInURL() {
    const form = document.getElementById('filter-form');
    if (!form) return;
    
    const formData = new FormData(form);
    const params = new URLSearchParams();
    
    // Add form data to URL params
    for (let [key, value] of formData.entries()) {
        if (value) {
            params.append(key, value);
        }
    }
    
    // Add price filter data
    const selectedPrices = Array.from(document.querySelectorAll('.price-filter .btn.active'))
        .map(btn => btn.textContent.trim());
    if (selectedPrices.length > 0) {
        params.append('PriceLevel', selectedPrices.join(','));
    }
    
    // Add suggestion filters
    const suggestions = Array.from(document.querySelectorAll('.suggested-filters input:checked'))
        .map(input => input.id);
    if (suggestions.length > 0) {
        params.append('Suggestions', suggestions.join(','));
    }
    
    console.log('Filter params:', params.toString());
    return params.toString();
}

// Enhanced Apply Filters functionality
document.addEventListener('DOMContentLoaded', function() {
    const applyFiltersBtn = document.getElementById('apply-filters-btn');
    if (applyFiltersBtn) {
        applyFiltersBtn.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Disable button temporarily
            this.disabled = true;
            this.innerHTML = '<div class="spinner-border spinner-border-sm me-2" role="status"></div>Đang tìm...';
            
            // Get the form
            const form = this.closest('form');
            if (form) {
                // Submit the form after a short delay to show loading
                setTimeout(() => {
                    form.submit();
                }, 300);
            }
        });
    }
});
