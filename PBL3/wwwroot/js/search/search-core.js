/**
 * Search Core Module
 * Main search functionality for the application
 * Phase 2+: Enhanced search with location services
 */
var SearchCore = (function() {
    'use strict';

    // Private variables
    var searchForm = null;
    var searchInput = null;
    var locationInput = null;
    var latInput = null;
    var lngInput = null;
    var searchButton = null;
    var locationDropdown = null;
    var useLocationButton = null;

    // Configuration
    var config = {
        minSearchLength: 2,
        maxSearchLength: 100,
        debounceDelay: 300
    };

    // Initialize the search module
    function init() {
        cacheDOM();
        bindEvents();
        setupUI();
    }

    // Cache DOM elements
    function cacheDOM() {
        searchForm = document.getElementById('navbarSearchForm');
        if (!searchForm) {
            console.warn('Search form not found');
            return;
        }

        searchInput = searchForm.querySelector('input[name="searchTerm"]');
        locationInput = document.getElementById('navbarLocationInput');
        latInput = document.getElementById('navbarLat');
        lngInput = document.getElementById('navbarLng');
        searchButton = searchForm.querySelector('button[type="submit"]');
        locationDropdown = document.getElementById('location-suggestion');
        useLocationButton = document.getElementById('navbarUseCurrentLocation');
    }

    // Bind event listeners
    function bindEvents() {
        if (!searchForm) return;

        // Form submission 
        searchForm.addEventListener('submit', handleSubmit);

        // Location input focus/blur
        if (locationInput) {
            locationInput.addEventListener('focus', showLocationDropdown);
            locationInput.addEventListener('blur', hideLocationDropdownDelayed);
        }

        // Use current location button
        if (useLocationButton) {
            useLocationButton.addEventListener('click', handleLocationButtonClick);
        }

        // Close dropdown when clicking outside
        document.addEventListener('click', handleDocumentClick);

        // Search input validation
        if (searchInput) {
            searchInput.addEventListener('input', validateSearchInput);
        }
    }    // Setup UI enhancements
    function setupUI() {
        // Disable autocomplete with multiple techniques
        if (searchForm) {
            searchForm.setAttribute('autocomplete', 'off');
            searchForm.setAttribute('data-form-type', 'other'); // Additional attribute to confuse browsers
        }
        
        // Apply enhanced autocomplete prevention to search input
        if (searchInput) {
            searchInput.setAttribute('autocomplete', 'off');
            searchInput.setAttribute('autocomplete', 'new-password'); // Another technique that works in some browsers
            searchInput.setAttribute('autocapitalize', 'off');
            searchInput.setAttribute('autocorrect', 'off');
            searchInput.setAttribute('spellcheck', 'false');
            
            // Randomize search input name
            var searchRandomSuffix = Math.floor(Math.random() * 1000000);
            searchInput.setAttribute('name', 'randomsearch-' + searchRandomSuffix);
        }
        
        if (locationInput) {
            locationInput.setAttribute('autocomplete', 'off');
            locationInput.setAttribute('autocomplete', 'new-password');
            locationInput.setAttribute('autocapitalize', 'off');
            locationInput.setAttribute('autocorrect', 'off');
            locationInput.setAttribute('spellcheck', 'false');
            
            // Randomize field name to prevent browser autocomplete
            var randomSuffix = Math.floor(Math.random() * 1000000);
            locationInput.setAttribute('name', 'randomloc-' + randomSuffix);
        }
    }    // Handle form submission
    function handleSubmit(event) {
        // Reset field names for proper form submission
        if (searchInput) {
            searchInput.setAttribute('name', 'searchTerm');
        }
        
        if (locationInput) {
            locationInput.setAttribute('name', 'Address');
        }

        var searchTerm = searchInput ? searchInput.value.trim() : '';
        var location = locationInput ? locationInput.value.trim() : '';        // Instead of validation errors, allow empty searches with default values
        // Allow form to proceed even if both fields are empty

        // Store search in history
        if (typeof SearchStorage !== 'undefined') {
            SearchStorage.addToHistory({
                searchTerm: searchTerm,
                location: location,
                timestamp: new Date().toISOString()
            });
        }

        // Show loading state
        showLoadingState();

        // Allow form to submit normally
        return true;
    }

    // Show location dropdown
    function showLocationDropdown() {
        if (locationDropdown) {
            locationDropdown.classList.add('show');
        }
    }

    // Hide location dropdown with delay
    function hideLocationDropdownDelayed() {
        setTimeout(function() {
            if (locationDropdown) {
                locationDropdown.classList.remove('show');
            }
        }, 200);
    }    // Handle location button click - Get current geolocation
    function handleLocationButtonClick(event) {
        event.preventDefault();
        event.stopPropagation();
        
        // Check if geolocation is available in browser
        if (!navigator.geolocation) {
            alert('Vị trí hiện tại không được hỗ trợ trong trình duyệt của bạn. Vui lòng nhập vị trí thủ công.');
            return;
        }
        
        // Show loading state on the button
        if (useLocationButton) {
            const originalText = useLocationButton.innerHTML;
            useLocationButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Đang lấy vị trí...';
            useLocationButton.disabled = true;
            
            // Store original button content for restoration later
            useLocationButton.dataset.originalText = originalText;
        }
        
        // Set timeout for geolocation request
        const geoOptions = {
            enableHighAccuracy: true,
            timeout: 10000,
            maximumAge: 0
        };
        
        // Request geolocation
        navigator.geolocation.getCurrentPosition(
            // Success handler
            function(position) {
                console.log('Got position:', position.coords.latitude, position.coords.longitude);
                
                // Update hidden fields with coordinates
                if (latInput) latInput.value = position.coords.latitude;
                if (lngInput) lngInput.value = position.coords.longitude;
                
                // Update location input with placeholder text
                if (locationInput) locationInput.value = 'Vị trí hiện tại của bạn';
                
                // Restore button state
                restoreLocationButton();
                
                // Hide dropdown
                if (locationDropdown) {
                    locationDropdown.classList.remove('show');
                }
                  // Reset field names for proper form submission (critical for controller to receive params)
                if (searchInput) {
                    searchInput.setAttribute('name', 'searchTerm');
                }
                
                if (locationInput) {
                    locationInput.setAttribute('name', 'Address');
                }
                
                // Auto-submit the form to update results with new location
                if (searchForm) {
                    showLoadingState();
                    searchForm.submit();
                }
            },
            // Error handler
            function(error) {
                console.error('Geolocation error:', error);
                
                let errorMessage;
                switch(error.code) {
                    case error.PERMISSION_DENIED:
                        errorMessage = 'Truy cập vị trí bị từ chối. Vui lòng cho phép truy cập vị trí trong cài đặt trình duyệt của bạn.';
                        break;
                    case error.POSITION_UNAVAILABLE:
                        errorMessage = 'Thông tin vị trí không có sẵn. Vui lòng thử lại sau.';
                        break;
                    case error.TIMEOUT:
                        errorMessage = 'Quá thời gian yêu cầu vị trí. Vui lòng thử lại.';
                        break;
                    default:
                        errorMessage = 'Lỗi không xác định khi lấy vị trí. Vui lòng thử lại sau.';
                }
                
                alert(errorMessage);
                
                // Restore button state
                restoreLocationButton();
            },
            // Options
            geoOptions
        );
    }
    
    // Helper function to restore location button state
    function restoreLocationButton() {
        if (useLocationButton && useLocationButton.dataset.originalText) {
            useLocationButton.innerHTML = useLocationButton.dataset.originalText;
            useLocationButton.disabled = false;
            delete useLocationButton.dataset.originalText;
        }
    }

    // Handle document click to close dropdown
    function handleDocumentClick(event) {
        if (!locationInput || !locationDropdown) return;

        if (!locationInput.contains(event.target) && 
            !locationDropdown.contains(event.target)) {
            locationDropdown.classList.remove('show');
        }
    }    // Validate search input as user types
    function validateSearchInput() {
        if (!searchInput) return;

        var value = searchInput.value.trim();
        // Allow empty searches - they will use default values
        if (value.length > 0 && value.length < config.minSearchLength) {
            // Only validate if there's text, but allow empty searches
            searchInput.setCustomValidity('Search term must be at least ' + config.minSearchLength + ' characters');
        } else if (value.length > config.maxSearchLength) {
            searchInput.setCustomValidity('Search term must be less than ' + config.maxSearchLength + ' characters');
        } else {
            searchInput.setCustomValidity('');
        }
    }

    // Show loading state
    function showLoadingState() {
        if (searchButton) {
            var originalText = searchButton.innerHTML;
            searchButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
            searchButton.disabled = true;

            // Store original text for restoration
            searchButton.dataset.originalText = originalText;
        }
    }

    // Hide loading state
    function hideLoadingState() {
        if (searchButton && searchButton.dataset.originalText) {
            searchButton.innerHTML = searchButton.dataset.originalText;
            searchButton.disabled = false;
            delete searchButton.dataset.originalText;
        }
    }

    // Get current search values
    function getCurrentSearchValues() {
        return {
            searchTerm: searchInput ? searchInput.value.trim() : '',
            location: locationInput ? locationInput.value.trim() : '',
            lat: latInput ? latInput.value : '',
            lng: lngInput ? lngInput.value : ''
        };
    }

    // Clear search form
    function clearForm() {
        if (searchInput) searchInput.value = '';
        if (locationInput) locationInput.value = '';
        if (latInput) latInput.value = '';
        if (lngInput) lngInput.value = '';
        
        SearchValidation.clearErrors();
    }

    // Set search values (useful for history restoration)
    function setSearchValues(values) {
        if (searchInput && values.searchTerm) {
            searchInput.value = values.searchTerm;
        }
        if (locationInput && values.location) {
            locationInput.value = values.location;
        }
        if (latInput && values.lat) {
            latInput.value = values.lat;
        }
        if (lngInput && values.lng) {
            lngInput.value = values.lng;
        }
    }

    // Public API
    return {
        init: init,
        getCurrentSearchValues: getCurrentSearchValues,
        clearForm: clearForm,
        setSearchValues: setSearchValues,
        showLoadingState: showLoadingState,
        hideLoadingState: hideLoadingState
    };
})();
