/**
 * Pagination functionality for search results
 */

document.addEventListener('DOMContentLoaded', () => {
    // Apply initial pagination styling (if pagination exists)
    initializePaginationVisibility();
});

/**
 * Load a specific page of search results
 * @param {number} pageNumber - The page number to load
 */
window.loadPage = function(pageNumber) {
    console.log('Loading page:', pageNumber);
    
    // Get current search parameters and update page parameter
    const params = new URLSearchParams(window.location.search);
    params.set('Page', pageNumber);
    
    // Show loading indicator
    const restaurantList = document.getElementById('restaurant-list');
    if (restaurantList) {
        restaurantList.innerHTML = '<div class="text-center py-5"><div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div></div>';
    }
    
    // Send AJAX request
    fetch(`/Search?${params.toString()}`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.text();
        })
        .then(html => {
            // Parse the response HTML
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            
            // Update restaurant list content
            const newRestaurantContent = doc.querySelector('#restaurant-list');
            if (newRestaurantContent && restaurantList) {
                restaurantList.innerHTML = newRestaurantContent.innerHTML;
            }
            
            // Update and enhance pagination
            updatePagination(doc, pageNumber);
            
            // Update URL without reloading page
            const newUrl = `${window.location.pathname}?${params.toString()}`;
            window.history.pushState({ path: newUrl }, '', newUrl);
            
            // Scroll to top of results
            document.querySelector('.results-header')?.scrollIntoView({ behavior: 'smooth' });
            
            // Reload restaurants on map
            if (typeof loadRestaurantsFromList === 'function') {
                loadRestaurantsFromList();
            }
            
            // Re-initialize restaurant card click handlers
            initializeRestaurantCardHandlers();
        })
        .catch(error => {
            console.error('Error:', error);
            if (restaurantList) {
                restaurantList.innerHTML = '<div class="alert alert-danger">Đã xảy ra lỗi khi tải dữ liệu. Vui lòng thử lại.</div>';
            }
        });
};

/**
 * Update pagination container with new HTML and ensure visibility
 * @param {Document} doc - The parsed document from AJAX response
 * @param {number} currentPage - The current page number
 */
function updatePagination(doc, currentPage) {
    const currentPaginationContainer = document.querySelector('.pagination-container');
    const newPaginationContainer = doc.querySelector('.pagination-container');
    
    if (!currentPaginationContainer || !newPaginationContainer) {
        console.warn('Pagination container not found');
        return;
    }
    
    // Update pagination HTML
    currentPaginationContainer.innerHTML = newPaginationContainer.innerHTML;
    
    // Apply pagination visibility enhancements (consolidated approach)
    applyPaginationVisibility(currentPage);
}

/**
 * Initialize pagination visibility and styling on page load
 */
function initializePaginationVisibility() {
    // Get current page from URL or default to 1
    const params = new URLSearchParams(window.location.search);
    const currentPage = parseInt(params.get('Page')) || 1;
    
    // Apply pagination styling
    applyPaginationVisibility(currentPage);
}

/**
 * Apply visibility and styling to pagination elements
 * @param {number} currentPage - The current page number for highlighting
 */
function applyPaginationVisibility(currentPage) {
    const paginationContainer = document.querySelector('.pagination-container');
    if (!paginationContainer) return;
    
    // Add visibility class to container
    paginationContainer.classList.add('pagination-visible');
    
    // Style navigation and pagination lists
    const paginationNav = paginationContainer.querySelector('nav');
    if (paginationNav) {
        paginationNav.classList.add('pagination-nav-visible');
        
        const paginationList = paginationNav.querySelector('.pagination');
        if (paginationList) {
            paginationList.classList.add('pagination-list-visible');
            
            // Style all page items and links
            const pageItems = paginationList.querySelectorAll('li');
            pageItems.forEach(item => {
                item.classList.add('page-item-visible');
                
                const pageLink = item.querySelector('a');
                if (pageLink) {
                    pageLink.classList.add('page-link-visible');
                    
                    // Highlight current page
                    const linkPage = parseInt(pageLink.textContent.trim());
                    if (!isNaN(linkPage) && linkPage === currentPage) {
                        pageLink.classList.add('current-page');
                    }
                }
            });
        }
    } else {
        // Handle links directly in container (fallback)
        const links = paginationContainer.querySelectorAll('a');
        links.forEach(link => {
            link.classList.add('page-link-visible');
            
            // Highlight current page
            const linkText = link.textContent.trim();
            const linkPage = parseInt(linkText);
            if (!isNaN(linkPage) && linkPage === currentPage) {
                link.classList.add('current-page');
            }
        });
    }
}
