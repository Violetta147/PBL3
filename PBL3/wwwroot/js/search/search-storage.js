/**
 * Search Storage Module
 * Local storage management for search history and preferences
 * Phase 2: Basic storage without location services
 */
var SearchStorage = (function() {
    'use strict';

    // Storage keys
    var storageKeys = {
        searchHistory: 'fishloot_search_history',
        searchPreferences: 'fishloot_search_preferences',
        lastSearch: 'fishloot_last_search'
    };

    // Configuration
    var config = {
        maxHistoryItems: 10,
        maxHistoryAge: 30 * 24 * 60 * 60 * 1000, // 30 days in milliseconds
        storageVersion: '1.0'
    };

    // Check if localStorage is available
    function isStorageAvailable() {
        try {
            var test = '__storage_test__';
            localStorage.setItem(test, test);
            localStorage.removeItem(test);
            return true;
        } catch(e) {
            console.warn('localStorage is not available');
            return false;
        }
    }

    // Get data from localStorage with error handling
    function getStorageData(key, defaultValue) {
        if (!isStorageAvailable()) return defaultValue;

        try {
            var data = localStorage.getItem(key);
            return data ? JSON.parse(data) : defaultValue;
        } catch(e) {
            console.warn('Error reading from localStorage:', e);
            return defaultValue;
        }
    }

    // Set data to localStorage with error handling
    function setStorageData(key, value) {
        if (!isStorageAvailable()) return false;

        try {
            localStorage.setItem(key, JSON.stringify(value));
            return true;
        } catch(e) {
            console.warn('Error writing to localStorage:', e);
            return false;
        }
    }

    // Add search to history
    function addToHistory(searchData) {
        if (!searchData || (!searchData.searchTerm && !searchData.location)) {
            return false;
        }

        var history = getHistory();
        
        // Create search entry
        var searchEntry = {
            searchTerm: searchData.searchTerm || '',
            location: searchData.location || '',
            timestamp: searchData.timestamp || new Date().toISOString(),
            id: generateId()
        };

        // Remove duplicates (same search term and location)
        history = history.filter(function(item) {
            return !(item.searchTerm === searchEntry.searchTerm && 
                    item.location === searchEntry.location);
        });

        // Add to beginning of array
        history.unshift(searchEntry);

        // Limit history size
        history = history.slice(0, config.maxHistoryItems);

        // Clean old entries
        history = cleanOldEntries(history);

        // Save to storage
        return setStorageData(storageKeys.searchHistory, history);
    }

    // Get search history
    function getHistory() {
        var history = getStorageData(storageKeys.searchHistory, []);
        return cleanOldEntries(history);
    }

    // Remove item from history by index
    function removeFromHistory(index) {
        var history = getHistory();
        if (index >= 0 && index < history.length) {
            history.splice(index, 1);
            return setStorageData(storageKeys.searchHistory, history);
        }
        return false;
    }

    // Clear all search history
    function clearHistory() {
        return setStorageData(storageKeys.searchHistory, []);
    }

    // Clean old entries from history
    function cleanOldEntries(history) {
        if (!Array.isArray(history)) return [];

        var cutoffDate = new Date(Date.now() - config.maxHistoryAge);
        
        return history.filter(function(item) {
            if (!item.timestamp) return false;
            
            try {
                var itemDate = new Date(item.timestamp);
                return itemDate > cutoffDate;
            } catch(e) {
                return false;
            }
        });
    }

    // Get search preferences
    function getPreferences() {
        return getStorageData(storageKeys.searchPreferences, {
            defaultPageSize: 10,
            defaultSortBy: 'relevance',
            rememberLastSearch: true,
            showSearchSuggestions: true
        });
    }

    // Set search preferences
    function setPreferences(preferences) {
        var currentPrefs = getPreferences();
        var newPrefs = Object.assign(currentPrefs, preferences);
        return setStorageData(storageKeys.searchPreferences, newPrefs);
    }

    // Save last search for restoration
    function saveLastSearch(searchData) {
        if (!searchData) return false;

        var lastSearch = {
            searchTerm: searchData.searchTerm || '',
            location: searchData.location || '',
            lat: searchData.lat || '',
            lng: searchData.lng || '',
            timestamp: new Date().toISOString()
        };

        return setStorageData(storageKeys.lastSearch, lastSearch);
    }

    // Get last search
    function getLastSearch() {
        var lastSearch = getStorageData(storageKeys.lastSearch, null);
        
        if (!lastSearch || !lastSearch.timestamp) return null;

        // Check if last search is too old (more than 1 day)
        try {
            var lastSearchDate = new Date(lastSearch.timestamp);
            var oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
            
            if (lastSearchDate < oneDayAgo) {
                return null;
            }
        } catch(e) {
            return null;
        }

        return lastSearch;
    }

    // Get popular searches (most frequent)
    function getPopularSearches(limit) {
        limit = limit || 5;
        var history = getHistory();
        
        // Count frequency of search terms
        var searchCounts = {};
        history.forEach(function(item) {
            if (item.searchTerm) {
                var term = item.searchTerm.toLowerCase().trim();
                searchCounts[term] = (searchCounts[term] || 0) + 1;
            }
        });

        // Convert to array and sort by frequency
        var popular = Object.keys(searchCounts).map(function(term) {
            return {
                searchTerm: term,
                count: searchCounts[term]
            };
        });

        popular.sort(function(a, b) {
            return b.count - a.count;
        });

        return popular.slice(0, limit);
    }

    // Export search data (for backup)
    function exportData() {
        return {
            history: getHistory(),
            preferences: getPreferences(),
            lastSearch: getLastSearch(),
            exportDate: new Date().toISOString(),
            version: config.storageVersion
        };
    }

    // Import search data (from backup)
    function importData(data) {
        if (!data || typeof data !== 'object') {
            return false;
        }

        var success = true;

        if (data.history && Array.isArray(data.history)) {
            success = setStorageData(storageKeys.searchHistory, data.history) && success;
        }

        if (data.preferences && typeof data.preferences === 'object') {
            success = setStorageData(storageKeys.searchPreferences, data.preferences) && success;
        }

        if (data.lastSearch && typeof data.lastSearch === 'object') {
            success = setStorageData(storageKeys.lastSearch, data.lastSearch) && success;
        }

        return success;
    }

    // Clear all search data
    function clearAllData() {
        var success = true;
        
        Object.values(storageKeys).forEach(function(key) {
            try {
                localStorage.removeItem(key);
            } catch(e) {
                success = false;
            }
        });

        return success;
    }

    // Generate unique ID for search entries
    function generateId() {
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    }

    // Get storage usage statistics
    function getStorageStats() {
        if (!isStorageAvailable()) {
            return {
                available: false,
                error: 'localStorage not available'
            };
        }

        try {
            var totalSize = 0;
            var itemCount = 0;

            Object.values(storageKeys).forEach(function(key) {
                var data = localStorage.getItem(key);
                if (data) {
                    totalSize += data.length;
                    itemCount++;
                }
            });

            return {
                available: true,
                totalSize: totalSize,
                itemCount: itemCount,
                historyCount: getHistory().length,
                lastCleanup: new Date().toISOString()
            };
        } catch(e) {
            return {
                available: false,
                error: e.message
            };
        }
    }

    // Initialize storage (cleanup old data, etc.)
    function init() {
        if (!isStorageAvailable()) {
            console.warn('SearchStorage: localStorage not available, search history disabled');
            return false;
        }

        // Clean old entries on init
        var history = getHistory();
        if (history.length > 0) {
            setStorageData(storageKeys.searchHistory, history);
        }

        console.log('SearchStorage initialized:', getStorageStats());
        return true;
    }

    // Public API
    return {
        init: init,
        addToHistory: addToHistory,
        getHistory: getHistory,
        removeFromHistory: removeFromHistory,
        clearHistory: clearHistory,
        getPreferences: getPreferences,
        setPreferences: setPreferences,
        saveLastSearch: saveLastSearch,
        getLastSearch: getLastSearch,
        getPopularSearches: getPopularSearches,
        exportData: exportData,
        importData: importData,
        clearAllData: clearAllData,
        getStorageStats: getStorageStats,
        isStorageAvailable: isStorageAvailable
    };
})();
