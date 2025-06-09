/**
 * Search Initialization
 * Main initialization script for search functionality
 * Phase 2: Basic search without location services
 */
(function() {
    'use strict';

    // Wait for DOM to be ready
    function domReady(callback) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', callback);
        } else {
            callback();
        }
    }

    // Initialize all search modules
    function initializeSearch() {
        console.log('Initializing search functionality...');

        // Check if required modules are loaded
        var requiredModules = ['SearchCore', 'SearchValidation', 'SearchUI', 'SearchStorage'];
        var missingModules = [];

        requiredModules.forEach(function(moduleName) {
            if (typeof window[moduleName] === 'undefined') {
                missingModules.push(moduleName);
            }
        });

        if (missingModules.length > 0) {
            console.warn('Missing search modules:', missingModules);
            return false;
        }

        try {
            // Initialize storage first
            SearchStorage.init();

            // Initialize core functionality
            SearchCore.init();

            // Initialize validation
            SearchValidation.setupRealTimeValidation();

            // Initialize UI enhancements
            SearchUI.init();

            // Restore last search if preferences allow it
            restoreLastSearch();

            // Setup global error handling
            setupErrorHandling();

            console.log('Search functionality initialized successfully');
            return true;

        } catch (error) {
            console.error('Error initializing search functionality:', error);
            return false;
        }
    }

    // Restore last search from storage
    function restoreLastSearch() {
        if (!SearchStorage.isStorageAvailable()) return;

        var preferences = SearchStorage.getPreferences();
        if (!preferences.rememberLastSearch) return;

        var lastSearch = SearchStorage.getLastSearch();
        if (!lastSearch) return;

        // Only restore if current inputs are empty
        var searchForm = document.getElementById('navbarSearchForm');
        if (!searchForm) return;

        var searchInput = searchForm.querySelector('input[name="searchTerm"]');
        var locationInput = searchForm.querySelector('input[name="Address"]');

        var shouldRestore = true;
        if (searchInput && searchInput.value.trim()) shouldRestore = false;
        if (locationInput && locationInput.value.trim()) shouldRestore = false;

        if (shouldRestore && typeof SearchCore !== 'undefined') {
            SearchCore.setSearchValues(lastSearch);
            console.log('Last search restored:', lastSearch);
        }
    }

    // Setup global error handling for search
    function setupErrorHandling() {
        // Handle search form errors
        var searchForm = document.getElementById('navbarSearchForm');
        if (searchForm) {
            searchForm.addEventListener('error', function(event) {
                console.error('Search form error:', event);
                if (typeof SearchValidation !== 'undefined') {
                    SearchValidation.showError('An error occurred while processing your search. Please try again.');
                }
            });
        }

        // Handle network errors during form submission
        window.addEventListener('online', function() {
            if (typeof SearchValidation !== 'undefined') {
                SearchValidation.showSuccess('Connection restored');
            }
        });

        window.addEventListener('offline', function() {
            if (typeof SearchValidation !== 'undefined') {
                SearchValidation.showError('You are offline. Search may not work properly.');
            }
        });
    }

    // Expose search manager globally for debugging
    window.FishlootSearch = {
        init: initializeSearch,
        modules: {
            core: function() { return typeof SearchCore !== 'undefined' ? SearchCore : null; },
            validation: function() { return typeof SearchValidation !== 'undefined' ? SearchValidation : null; },
            ui: function() { return typeof SearchUI !== 'undefined' ? SearchUI : null; },
            storage: function() { return typeof SearchStorage !== 'undefined' ? SearchStorage : null; }
        },
        debug: {
            getStorageStats: function() {
                return typeof SearchStorage !== 'undefined' ? SearchStorage.getStorageStats() : null;
            },
            exportData: function() {
                return typeof SearchStorage !== 'undefined' ? SearchStorage.exportData() : null;
            },
            clearAllData: function() {
                return typeof SearchStorage !== 'undefined' ? SearchStorage.clearAllData() : false;
            }
        }
    };

    // Initialize when DOM is ready
    domReady(function() {
        // Small delay to ensure all scripts are loaded
        setTimeout(initializeSearch, 100);
    });

})();
