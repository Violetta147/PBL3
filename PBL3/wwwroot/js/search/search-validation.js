/**
 * Search Validation Module
 * Form validation functionality for search
 * Phase 2: Basic validation without location services
 */
var SearchValidation = (function() {
    'use strict';

    // Validation rules
    var validationRules = {
        searchTerm: {
            minLength: 2,
            maxLength: 100,
            pattern: /^[a-zA-Z0-9\s\-\.,!?'"()áàảãạăắằẳẵặâấầẩẫậéèẻẽẹêếềểễệíìỉĩịóòỏõọôốồổỗộơớờởỡợúùủũụưứừửữựýỳỷỹỵđ]+$/i
        },
        location: {
            minLength: 2,
            maxLength: 200,
            pattern: /^[a-zA-Z0-9\s\-\.,()áàảãạăắằẳẵặâấầẩẫậéèẻẽẹêếềểễệíìỉĩịóòỏõọôốồổỗộơớờởỡợúùủũụưứừửữựýỳỷỹỵđ]+$/i
        }
    };

    // Error messages
    var errorMessages = {
        required: 'Vui lòng nhập từ khóa tìm kiếm hoặc địa điểm',
        searchTermTooShort: 'Từ khóa tìm kiếm phải có ít nhất {min} ký tự',
        searchTermTooLong: 'Từ khóa tìm kiếm không được vượt quá {max} ký tự',
        searchTermInvalid: 'Từ khóa tìm kiếm chứa ký tự không hợp lệ',
        locationTooShort: 'Địa điểm phải có ít nhất {min} ký tự',
        locationTooLong: 'Địa điểm không được vượt quá {max} ký tự',
        locationInvalid: 'Địa điểm chứa ký tự không hợp lệ'
    };

    // Validate search term
    function validateSearchTerm(value) {
        if (!value || value.trim() === '') {
            return { valid: true, message: '' }; // Optional field
        }

        var trimmed = value.trim();
        var rules = validationRules.searchTerm;

        if (trimmed.length < rules.minLength) {
            return { 
                valid: false, 
                message: errorMessages.searchTermTooShort.replace('{min}', rules.minLength)
            };
        }

        if (trimmed.length > rules.maxLength) {
            return { 
                valid: false, 
                message: errorMessages.searchTermTooLong.replace('{max}', rules.maxLength)
            };
        }

        if (!rules.pattern.test(trimmed)) {
            return { 
                valid: false, 
                message: errorMessages.searchTermInvalid
            };
        }

        return { valid: true, message: '' };
    }

    // Validate location
    function validateLocation(value) {
        if (!value || value.trim() === '') {
            return { valid: true, message: '' }; // Optional field
        }

        var trimmed = value.trim();
        var rules = validationRules.location;

        if (trimmed.length < rules.minLength) {
            return { 
                valid: false, 
                message: errorMessages.locationTooShort.replace('{min}', rules.minLength)
            };
        }

        if (trimmed.length > rules.maxLength) {
            return { 
                valid: false, 
                message: errorMessages.locationTooLong.replace('{max}', rules.maxLength)
            };
        }

        if (!rules.pattern.test(trimmed)) {
            return { 
                valid: false, 
                message: errorMessages.locationInvalid
            };
        }

        return { valid: true, message: '' };
    }

    // Validate entire form
    function validateForm(formData) {
        var errors = [];
        
        // At least one field must be filled
        if (!formData.searchTerm && !formData.location) {
            errors.push(errorMessages.required);
        }

        // Validate individual fields
        var searchTermValidation = validateSearchTerm(formData.searchTerm);
        if (!searchTermValidation.valid) {
            errors.push(searchTermValidation.message);
        }

        var locationValidation = validateLocation(formData.location);
        if (!locationValidation.valid) {
            errors.push(locationValidation.message);
        }

        return {
            valid: errors.length === 0,
            errors: errors
        };
    }

    // Show validation error
    function showError(message, field) {
        // Remove existing error messages
        clearErrors();

        // Create error element
        var errorElement = document.createElement('div');
        errorElement.className = 'search-validation-error';
        errorElement.textContent = message;
        errorElement.style.cssText = `
            color: #dc3545;
            font-size: 12px;
            margin-top: 4px;
            padding: 6px 12px;
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 4px;
            position: absolute;
            z-index: 1001;
            max-width: 300px;
            top: 100%;
            left: 0;
            right: 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        `;

        // Find target element
        var targetElement = field ? document.querySelector(`[name="${field}"]`) : 
                           document.getElementById('navbarSearchForm');
        
        if (targetElement) {
            var container = targetElement.closest('.fishloot-search-container') || 
                           targetElement.parentNode;
            
            if (container) {
                container.style.position = 'relative';
                container.appendChild(errorElement);
                
                // Auto-hide after 5 seconds
                setTimeout(function() {
                    if (errorElement.parentNode) {
                        errorElement.parentNode.removeChild(errorElement);
                    }
                }, 5000);
            }
        }
    }

    // Show success message
    function showSuccess(message) {
        clearErrors();

        var successElement = document.createElement('div');
        successElement.className = 'search-validation-success';
        successElement.textContent = message;
        successElement.style.cssText = `
            color: #155724;
            font-size: 12px;
            margin-top: 4px;
            padding: 6px 12px;
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 4px;
            position: absolute;
            z-index: 1001;
            max-width: 300px;
            top: 100%;
            left: 0;
            right: 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        `;

        var searchForm = document.getElementById('navbarSearchForm');
        if (searchForm) {
            var container = searchForm.closest('.fishloot-search-container') || searchForm;
            container.style.position = 'relative';
            container.appendChild(successElement);
            
            setTimeout(function() {
                if (successElement.parentNode) {
                    successElement.parentNode.removeChild(successElement);
                }
            }, 3000);
        }
    }

    // Clear validation messages
    function clearErrors() {
        var existingMessages = document.querySelectorAll('.search-validation-error, .search-validation-success');
        existingMessages.forEach(function(element) {
            if (element.parentNode) {
                element.parentNode.removeChild(element);
            }
        });
    }

    // Sanitize input to prevent XSS
    function sanitizeInput(input) {
        if (typeof input !== 'string') return '';
        
        return input
            .trim()
            .replace(/[<>]/g, '') // Remove basic HTML tags
            .substring(0, 200); // Limit length
    }

    // Real-time validation for input fields
    function setupRealTimeValidation() {
        var searchInput = document.querySelector('input[name="searchTerm"]');
        var locationInput = document.querySelector('input[name="Address"]');

        if (searchInput) {
            searchInput.addEventListener('blur', function() {
                var validation = validateSearchTerm(this.value);
                if (!validation.valid && this.value.trim()) {
                    showError(validation.message, 'searchTerm');
                }
            });

            searchInput.addEventListener('input', function() {
                clearErrors();
            });
        }

        if (locationInput) {
            locationInput.addEventListener('blur', function() {
                var validation = validateLocation(this.value);
                if (!validation.valid && this.value.trim()) {
                    showError(validation.message, 'Address');
                }
            });

            locationInput.addEventListener('input', function() {
                clearErrors();
            });
        }
    }

    // Public API
    return {
        validateSearchTerm: validateSearchTerm,
        validateLocation: validateLocation,
        validateForm: validateForm,
        showError: showError,
        showSuccess: showSuccess,
        clearErrors: clearErrors,
        sanitizeInput: sanitizeInput,
        setupRealTimeValidation: setupRealTimeValidation
    };
})();
