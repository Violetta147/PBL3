// Search Map Functionality with Clustering and Spiderifier
let map;
let markers = [];
let currentPopup = null;
let mapisDragging = false;
let mapMoved = false;
let spiderifier = null;
let currentZoomLevel = 0;
let scatteredMarkersActive = false; // Track whether scattered markers are currently displayed
let scatterCheckInProgress = false; // Prevent infinite loops when checking scatter conditions
let lastScatterCheck = 0; // Timestamp of last scatter check for debouncing
let currentScatterState = 'original'; // Track current state: 'original', 'scattered'
let zoomChangeInProgress = false; // Track if zoom change is in progress
let manualScatterActive = false; // Track if scattering was triggered manually (cluster clicks) vs automatically (zoom)

// Initialize map when page loads
document.addEventListener('DOMContentLoaded', function () {
    console.log('Initializing search map with clustering and spiderifier...');
    initializeMap();
});

function initializeMap() {
    // Get map configuration from hidden inputs
    const mapboxToken = document.getElementById('mapbox-token')?.value;
    const initialLat = parseFloat(document.getElementById('map-initial-lat')?.value || '16.047079');
    console.log('Initial latitude:', isNaN(initialLat) ? 'Invalid' : initialLat);
    const initialLng = parseFloat(document.getElementById('map-initial-lng')?.value || '108.206230');
    console.log('Initial longitude:', isNaN(initialLng) ? 'Invalid' : initialLng);

    if (!mapboxToken) {
        console.warn('Mapbox token not found. Map will not be initialized.');
        showMapError('Map configuration missing');
        return;
    }

    console.log('Map config:', { lat: initialLat, lng: initialLng });

    try {        // Set Mapbox access token
        mapboxgl.accessToken = mapboxToken;
        console.log('Mapbox access token set:', mapboxgl.accessToken);
        
        // Initialize map
        map = new mapboxgl.Map({
            container: 'mapbox-container',
            style: 'mapbox://styles/mapbox/streets-v12',
            center: [initialLng, initialLat],
            zoom: 12,
            language: 'vi'
        });

        // Add navigation controls
        map.addControl(new mapboxgl.NavigationControl(), 'top-right');        // Store initial zoom level
        currentZoomLevel = map.getZoom();
        console.log('Initial zoom level:', currentZoomLevel);        // Add event listener for zoom changes - only use idle event to avoid conflicts
        map.on('zoom', function () {
            const newZoomLevel = map.getZoom();
            console.log('Current zoom level:', newZoomLevel);
            
            // If we're zooming out from scatter mode and have an open popup, close it
            if (currentZoomLevel >= 15 && newZoomLevel < 15 && currentPopup) {
                console.log('Zooming out from scatter mode, checking popup type');
                // Check if this popup is from scattered markers by checking its class
                const popupElement = currentPopup.getElement();
                if (popupElement && popupElement.classList.contains('scattered-popup')) {
                    console.log('Confirmed popup is from scattered marker, removing');
                    currentPopup.remove();
                    currentPopup = null;
                } else {
                    console.log('Popup is not from scattered marker, keeping it');
                }
            }
            
            currentZoomLevel = newZoomLevel;
            zoomChangeInProgress = true; // Mark that zoom is changing
        });
          
        map.on('zoomend', function () {
            const finalZoomLevel = map.getZoom();
            zoomChangeInProgress = false; // Mark that zoom change is complete
            console.log('Zoom ended at level:', finalZoomLevel);
            
            // Additional cleanup when zoom ends - ensure cluster click handlers are still active
            // This helps with the issue where clusters become unclickable after zooming
            if (finalZoomLevel < 15) {
                // If we zoomed out below scatter threshold, ensure any scattered marker popup is closed
                // Double-check for any remaining scattered popups that might not have been caught during zoom
                if (currentPopup) {
                    const popupElement = currentPopup.getElement();
                    if (popupElement && popupElement.classList.contains('scattered-popup')) {
                        console.log('Zoom ended below scatter threshold, closing scattered marker popup');
                        currentPopup.remove();
                        currentPopup = null;
                    }
                }
                
                // Also check for any scattered popups that might exist without being tracked in currentPopup
                const allScatteredPopups = document.querySelectorAll('.mapboxgl-popup.scattered-popup');
                if (allScatteredPopups.length > 0) {
                    console.log(`Found ${allScatteredPopups.length} untracked scattered popups, removing them`);
                    allScatteredPopups.forEach(popup => {
                        const closeButton = popup.querySelector('.mapboxgl-popup-close-button');
                        if (closeButton) {
                            closeButton.click();
                        } else {
                            popup.remove();
                        }
                    });
                }
                
                // Re-ensure cluster event handlers are active
                setTimeout(() => {
                    const clusterLayer = map.getLayer('clusters');
                    if (clusterLayer) {
                        console.log('Re-verifying cluster click handlers after zoom end');
                        ensureClusterClickHandlers();
                    }
                }, 100);
            }
        });
        
        // Wait for map to load before adding markers
        map.on('load', function () {
            console.log('Map loaded successfully');
            console.log('Map zoom level at load:', map.getZoom());            // Add event listener to check for scatter view when map becomes idle
            // (after panning, zooming, etc.) - use only this event to avoid double-triggering
            map.on('idle', function() {
                // Prevent feedback loops from our own operations with enhanced checks
                if (!scatterCheckInProgress && !zoomChangeInProgress) {
                    // Add debouncing to prevent rapid successive calls
                    const now = Date.now();
                    if (now - lastScatterCheck < 500) { // 500ms debounce
                        console.log('Debouncing scatter check, too soon since last check');
                        return;
                    }
                    
                    lastScatterCheck = now;
                    // Check if we need to scatter markers based on current zoom level
                    checkZoomForScatterView(map.getZoom());
                }
            });

            // Initialize spiderifier after map loads
            console.log('Initializing spiderifier...');
            try {
                // Check if MapboxglSpiderifier exists
                if (typeof MapboxglSpiderifier === 'undefined') {
                    console.error('MapboxglSpiderifier is not defined! Make sure the library is properly loaded.');
                    return;
                }

                console.log('MapboxglSpiderifier constructor found, initializing...');
                spiderifier = new MapboxglSpiderifier(map, {
                    animate: true,
                    animationSpeed: 300, // Slightly slower for better visibility
                    customPin: false,
                    radius: 100, // Further increased radius for better visibility
                    circleFootSeparation: 60, // Further increased separation
                    spiralFootSeparation: 45, // Further increased separation
                    spiralLengthStart: 30, // Start the spiral even further away
                    spiralLengthFactor: 5, // Increased factor for better spacing
                    initializeLeg: function (pin, feature) {
                        console.log('Initializing spiderifier leg for feature:', feature);

                        // Enhanced styling for pins
                        pin.style.backgroundColor = '#dc3545';
                        pin.style.border = '2px solid white';
                        pin.style.width = '36px';
                        pin.style.height = '36px';
                        pin.style.borderRadius = '50%';
                        pin.style.display = 'flex';
                        pin.style.alignItems = 'center';
                        pin.style.justifyContent = 'center';
                        pin.style.color = 'white';
                        pin.style.fontWeight = 'bold';
                        pin.style.fontSize = '14px';
                        pin.style.boxShadow = '0 3px 6px rgba(0,0,0,0.3)';
                        pin.style.transition = 'all 0.2s ease-in-out';

                        // Use different colors for different restaurant types if available
                        if (feature.properties && feature.properties.cuisineType) {
                            const cuisineType = feature.properties.cuisineType.toLowerCase();
                            if (cuisineType.includes('vietnamese')) {
                                pin.style.backgroundColor = '#d32f2f'; // Red
                            } else if (cuisineType.includes('italian')) {
                                pin.style.backgroundColor = '#388e3c'; // Green
                            } else if (cuisineType.includes('japanese')) {
                                pin.style.backgroundColor = '#1976d2'; // Blue
                            } else if (cuisineType.includes('chinese')) {
                                pin.style.backgroundColor = '#ffa000'; // Amber
                            }
                        }

                        // Display the number/index or another identifier
                        if (feature.properties && feature.properties.index) {
                            pin.textContent = feature.properties.index;
                        } else if (feature.properties && feature.properties.number) {
                            pin.textContent = feature.properties.number;
                        } else if (feature.properties && feature.properties.name) {
                            // If no index, try first letter of name
                            pin.textContent = feature.properties.name.charAt(0).toUpperCase();
                        } else {
                            // Fallback
                            pin.textContent = "#";
                        }

                        // Add hover effect event listeners
                        pin.addEventListener('mouseenter', function () {
                            pin.style.transform = 'scale(1.1)';
                            pin.style.boxShadow = '0 4px 8px rgba(0,0,0,0.4)';
                        });

                        pin.addEventListener('mouseleave', function () {
                            pin.style.transform = 'scale(1)';
                            pin.style.boxShadow = '0 3px 6px rgba(0,0,0,0.3)';
                        });                        console.log('Leg pin styled:', pin.style.cssText);
                    },
                    
                    onClick: function (e, feature) {
                        e.stopPropagation(); // Prevent event bubbling
                        console.log('Spider leg clicked:', e, feature);
                        
                        if (currentPopup) currentPopup.remove();
                        
                        let popupCoords;
                        
                        try {
                            // First priority: Try to use the pre-calculated visual coordinates
                            if (e.pinLngLat && e.pinLngLat.lng && e.pinLngLat.lat && e.pinLngLat.isVisual) {
                                console.log('Using pre-calculated visual LngLat for popup:', e.pinLngLat);
                                popupCoords = e.pinLngLat;
                            }
                            // Second priority: Calculate coordinates from screen position
                            else if (e.pinPosition && e.pinPosition.clientX && e.pinPosition.clientY) {
                                console.log('Using pin screen position for popup:', e.pinPosition);
                                
                                // Create a point using the spider leg pin's screen position
                                const point = {
                                    x: e.pinPosition.clientX,
                                    y: e.pinPosition.clientY
                                };
                                
                                // Get the point relative to map container if needed
                                const container = map.getContainer();
                                const rect = container.getBoundingClientRect();
                                
                                // For Mapbox GL, we can check if we need to adjust the point
                                // Some implementations need this adjustment, others don't
                                const mapPoint = {
                                    x: point.x - rect.left,
                                    y: point.y - rect.top
                                };
                                
                                // Convert screen coordinates to map coordinates
                                // First try with direct clientX/Y coordinates
                                try {
                                    popupCoords = map.unproject(point);
                                    console.log('Unprojected from client coordinates:', popupCoords);
                                } catch (err) {
                                    // If that fails, try with adjusted mapPoint
                                    console.log('Trying with adjusted map point:', mapPoint);
                                    popupCoords = map.unproject(mapPoint);
                                }
                            } 
                            // Third priority: Use data attributes from the pin element
                            else if (e.target && e.target.getAttribute) {
                                const lng = parseFloat(e.target.getAttribute('data-lng'));
                                const lat = parseFloat(e.target.getAttribute('data-lat'));
                                
                                if (!isNaN(lng) && !isNaN(lat)) {
                                    console.log('Using data attributes for popup position:', {lng, lat});
                                    popupCoords = { lng, lat };
                                } else {
                                    throw new Error('Invalid data attributes');
                                }
                            }
                            // Last priority: Fallback to original feature coordinates
                            else {
                                console.log('Fallback: Using original feature coordinates');
                                popupCoords = {
                                    lng: feature.geometry.coordinates[0],
                                    lat: feature.geometry.coordinates[1]
                                };
                            }
                        } catch (error) {
                            console.error('Error calculating popup position:', error);
                            // Last resort fallback
                            popupCoords = {
                                lng: feature.geometry.coordinates[0],
                                lat: feature.geometry.coordinates[1]
                            };
                            console.log('Error fallback: Using original coordinates:', popupCoords);                        }
                        
                        // Create and show the popup
                        const popup = new mapboxgl.Popup({
                            closeButton: false,
                            closeOnClick: true,
                            className: 'spider-popup',
                            maxWidth: '300px',
                            offset: [0, -18],
                            anchor: 'bottom'
                        }).setHTML(feature.properties.popupContent);
                        
                        // Set popup position and display
                        popup.setLngLat(popupCoords);
                        popup.addTo(map);
                        currentPopup = popup;
                        
                        console.log('Popup created at coordinates:', popupCoords);
                    }

                });

                console.log('Spiderifier initialized successfully');
            } catch (error) {
                console.error('Error initializing spiderifier:', error);
                spiderifier = null;
            }

            // Load restaurants after initializing the spiderifier
            loadRestaurantsFromList();
        });

        // Hide POI labels when style loads
        map.on('style.load', () => {
            map.getStyle().layers.forEach(function (layer) {
                if (layer.id.includes('poi') || layer.id.includes('poi-label')) {
                    map.setLayoutProperty(layer.id, 'visibility', 'none');
                }
            });
            console.log('POI labels hidden');
        });

        map.on('error', function (e) {
            console.error('Map error:', e);
            showMapError('Failed to load map');
        });

    } catch (error) {
        console.error('Error initializing map:', error);
        showMapError('Map initialization failed');
    }
}

function showMapError(message) {
    const mapContainer = document.getElementById('mapbox-container');
    if (mapContainer) {
        mapContainer.innerHTML = `
            <div class="d-flex align-items-center justify-content-center h-100 text-muted">
                <div class="text-center">
                    <i class="bi bi-geo-alt display-4 mb-3"></i>
                    <p class="mb-0">${message}</p>
                    <button class="btn btn-outline-primary btn-sm mt-2" onclick="location.reload()">
                        Thử lại
                    </button>
                </div>
            </div>`;
    }
}

// Load restaurants from the current page and add markers
function loadRestaurantsFromList() {
    if (!map) {
        console.warn('Map not initialized');
        return;
    }

    console.log('Loading restaurants from list...');

    // Clear existing markers
    clearMarkers();

    // Clear any spiderifier markers
    if (spiderifier) {
        spiderifier.unspiderfy();
    }

    // Get restaurant cards from the page
    const restaurantCards = document.querySelectorAll('.restaurant-item');
    console.log('Found restaurant cards:', restaurantCards.length);

    const bounds = new mapboxgl.LngLatBounds();
    let markersAdded = 0;

    // Create an array to store GeoJSON features for clustering
    const features = [];

    // Check if we already have the cluster source and layer
    const hasClusterSource = map.getSource('restaurants');
    if (hasClusterSource) {
        // Remove existing layers and source if they exist
        if (map.getLayer('clusters')) map.removeLayer('clusters');
        if (map.getLayer('cluster-count')) map.removeLayer('cluster-count');
        if (map.getLayer('unclustered-point')) map.removeLayer('unclustered-point');
        if (map.getLayer('unclustered-point-label')) map.removeLayer('unclustered-point-label');
        map.removeSource('restaurants');
        console.log('Removed existing cluster layers and source');
    }    // Process restaurant cards and create features for clustering
    restaurantCards.forEach((card, index) => {
        const lat = parseFloat(card.dataset.lat);
        const lng = parseFloat(card.dataset.lng);
        const name = card.dataset.name || card.querySelector('.card-title')?.textContent || 'Unknown Restaurant';
        const rating = card.dataset.rating || card.querySelector('.fw-bold')?.nextElementSibling?.textContent || 'N/A';
        const reviewCount = card.dataset.reviewCount || card.querySelector('.text-muted.small')?.textContent.match(/\((\d+) reviews\)/)?.[1] || '0';
        const address = card.dataset.address || card.querySelector('.bi-geo-alt')?.parentNode?.textContent.trim() || '';
        const id = card.dataset.id;

        console.log(`Processing card ${index + 1}:`, {
            name: name,
            rating: rating, 
            reviewCount: reviewCount,
            address: address,
            coordinates: { lat, lng },
            hasValidCoords: !isNaN(lat) && !isNaN(lng)
        });

        if (lat && lng && !isNaN(lat) && !isNaN(lng)) {
            console.log(`Adding feature for: ${name} at (${lat}, ${lng})`);

            // Create popup content
            const popupContent = createPopupContent(name, rating, reviewCount, address, id);

            // Add feature to the features array for clustering
            features.push({
                type: 'Feature',
                properties: {
                    id: id.toString(),
                    name: name,
                    rating: rating,
                    reviewCount: reviewCount,
                    address: address,
                    index: index + 1,
                    popupContent: popupContent,
                    number: (index + 1).toString()
                },
                geometry: {
                    type: 'Point',
                    coordinates: [lng, lat]
                }
            });

            bounds.extend([lng, lat]);
            markersAdded++;
        }
    });

    console.log(`Added ${markersAdded} features to map`);

    // Fit map to show all markers if any were added
    if (markersAdded > 0) {
        try {
            map.fitBounds(bounds, {
                padding: { top: 50, bottom: 50, left: 50, right: 50 },
                maxZoom: 15
            });
        } catch (error) {
            console.warn('Error fitting bounds:', error);
        }        // Add cluster layers if features exist
        if (features.length > 0) {
            console.log('Setting up clustering with features:', features.length);
            
            // Add a new source with clustering enabled
            map.addSource('restaurants', {
                type: 'geojson',
                data: {
                    type: 'FeatureCollection',
                    features: features
                },
                cluster: true,
                clusterMaxZoom: 16, // Max zoom to cluster points on (at zoom 15+ our scatter algorithm takes over)
                clusterRadius: 50 // Radius of each cluster when clustering points
            });

            // Add cluster circles layer
            map.addLayer({
                id: 'clusters',
                type: 'circle',
                source: 'restaurants',
                filter: ['has', 'point_count'],
                paint: {
                    'circle-color': [
                        'step',
                        ['get', 'point_count'],
                        '#dc3545', // Red for small clusters
                        10, // Step threshold
                        '#ff9800', // Orange for medium clusters 
                        30, // Step threshold
                        '#3f51b5' // Blue for large clusters
                    ],
                    'circle-radius': [
                        'step',
                        ['get', 'point_count'],
                        20, // Size for small clusters
                        10, // Step threshold
                        25, // Size for medium clusters
                        30, // Step threshold
                        30 // Size for large clusters
                    ],
                    'circle-stroke-width': 1,
                    'circle-stroke-color': '#fff'
                }
            });

            // Add count labels
            map.addLayer({
                id: 'cluster-count',
                type: 'symbol',
                source: 'restaurants',
                filter: ['has', 'point_count'],
                layout: {
                    'text-field': '{point_count_abbreviated}',
                    'text-font': ['DIN Offc Pro Medium', 'Arial Unicode MS Bold'],
                    'text-size': 12
                },
                paint: {
                    'text-color': '#ffffff'
                }
            });                // Handle clicks on clusters
            map.on('click', 'clusters', function (e) {
                const features = map.queryRenderedFeatures(e.point, { layers: ['clusters'] });
                if (!features || features.length === 0) {
                    console.warn('No cluster features found at click point');
                    return;
                } 
                const clusterId = features[0].properties.cluster_id;
                const clusterCenter = features[0].geometry.coordinates;
                const pointCount = features[0].properties.point_count;
                const currentZoom = map.getZoom();

                console.log(`Cluster clicked: ID ${clusterId}, contains ${pointCount} points`);
                console.log(`Current zoom level when cluster clicked: ${currentZoom}`);
                console.log(`Tracked zoom level: ${currentZoomLevel}`);

                // Close any existing popup
                if (currentPopup) {
                    currentPopup.remove();
                    currentPopup = null;
                }

                // Track if visualization was successfully applied
                let visualizationApplied = false;                // Clear any existing scattered markers
                if (window.scatteredMarkers) {
                    cleanupScatteredMarkers();
                }
                
                // If spiderifier is active, unspiderfy
                if (spiderifier) {
                    spiderifier.unspiderfy();
                }

                // Get all points in this cluster
                map.getSource('restaurants').getClusterLeaves(
                    clusterId,
                    pointCount, // limit - get all points
                    0, // offset
                    function (err, clusterFeatures) {
                        if (err) {
                            console.error('Error getting cluster leaves:', err);
                            fallbackToZoom();
                            return;
                        }                        console.log(`Retrieved ${clusterFeatures.length} points from cluster`);

                        // Debug the condition logic
                        console.log('=== CLUSTER CLICK CONDITION EVALUATION ===');
                        console.log('Current zoom:', currentZoom);
                        console.log('Zoom >= 15?', currentZoom >= 15);
                        console.log('Cluster features length:', clusterFeatures.length);
                        console.log('Features > 3?', clusterFeatures.length > 3);
                        console.log('Combined condition (zoom >= 15 && features > 3):', currentZoom >= 15 && clusterFeatures.length > 3);

                        // For small clusters (≤3 items), always use spider legs regardless of zoom
                        // For larger clusters at high zoom (≥15), use scattered markers to avoid overlap
                        if (currentZoom >= 15 && clusterFeatures.length > 3) {
                            try {
                                console.log('=== MANUAL SCATTERING TRIGGERED BY CLUSTER CLICK (LARGE CLUSTER) ===');
                                console.log('Large cluster detected:', clusterFeatures.length, 'items at zoom', currentZoom);
                                manualScatterActive = true; // Set manual scatter flag
                                // Use the new scatter marker algorithm with correct parameters
                                visualizationApplied = scatterMarkers(clusterFeatures, 0);
                                console.log('Scattered markers applied successfully:', visualizationApplied);
                            } catch (error) {
                                console.error('Error applying scattered markers:', error);
                                fallbackToZoom();
                            }
                        }                        // Use spider legs for all other clusters (small clusters or any cluster at lower zoom)
                        else if (spiderifier && clusterFeatures.length > 1) {
                            // Apply spiderifier to show all points in this cluster
                            try {
                                console.log('=== SPIDERIFIER PATH REACHED IN CLUSTER CLICK ===');
                                console.log('Using spider legs because:');
                                console.log('- Zoom < 15 OR cluster size <= 3');
                                console.log('- Current zoom:', currentZoom);
                                console.log('- Cluster features count:', clusterFeatures.length);
                                console.log('- Cluster center:', clusterCenter);
                                console.log('- Spiderifier instance:', spiderifier);
                                
                                // Create LngLat object from cluster center coordinates
                                const centerLngLat = new mapboxgl.LngLat(clusterCenter[0], clusterCenter[1]);                                // Spiderify the cluster features - this method doesn't return anything
                                console.log('Calling spiderifier.spiderfy with center:', clusterCenter);
                                spiderifier.spiderfy(clusterCenter, clusterFeatures);
                                
                                console.log('Spiderifier executed successfully');

                                // The spiderifier creates DOM elements directly, so we need to wait a bit
                                // for them to be created, then add our click handlers
                                setTimeout(() => {
                                    const spiderPins = document.querySelectorAll('.spider-leg-pin');
                                    console.log('Found spider pins:', spiderPins.length);
                                    
                                    spiderPins.forEach((pin, index) => {
                                        const featureId = pin.getAttribute('data-feature-id');
                                        const feature = clusterFeatures[parseInt(featureId)] || clusterFeatures[index];
                                        
                                        if (feature) {
                                            pin.onclick = function (e) {
                                                e.stopPropagation();
                                                console.log('Spider pin clicked:', feature);
                                                
                                                // Close any existing popup
                                                if (currentPopup) {
                                                    currentPopup.remove();
                                                    currentPopup = null;
                                                }
                                                
                                                // Get coordinates from the pin's data attributes (visual position)
                                                const lng = parseFloat(pin.getAttribute('data-lng') || feature.geometry.coordinates[0]);
                                                const lat = parseFloat(pin.getAttribute('data-lat') || feature.geometry.coordinates[1]);                                                  // Create and display popup for the spider leg
                                                const popup = new mapboxgl.Popup({
                                                    closeButton: false,
                                                    closeOnClick: true,
                                                    className: 'spider-popup',
                                                    maxWidth: '300px'
                                                })
                                                .setLngLat([lng, lat])
                                                .setHTML(feature.properties.popupContent)
                                                .addTo(map);
                                                currentPopup = popup;
                                                lastPopupOpenedTime = Date.now();
                                                
                                                console.log('Spider popup created with high z-index at:', [lng, lat]);
                                            };
                                        }
                                    });
                                }, 100); // Small delay to ensure DOM elements are created

                                // Add listeners to unspiderify when clicking elsewhere or moving the map
                                let unspiderifyOnClickOutside; 
                                let unspiderifyOnMove;

                                    unspiderifyOnClickOutside = function (event) {
                                        let clickedOnSpiderLeg = false;
                                        if (event.originalEvent && event.originalEvent.target) {
                                            const target = event.originalEvent.target;
                                            if (target.classList && (target.classList.contains('spider-leg-pin') || target.closest('.spider-leg-pin'))) {
                                                clickedOnSpiderLeg = true;
                                            }
                                        }
                                        
                                        let clickedOnOriginalCluster = false;
                                        const clickedClusterFeatures = map.queryRenderedFeatures(event.point, { layers: ['clusters'] });
                                        if (clickedClusterFeatures.some(feature => feature.properties.cluster_id === clusterId)) {
                                            clickedOnOriginalCluster = true;
                                        }

                                        if (!clickedOnSpiderLeg && !clickedOnOriginalCluster) {
                                            console.log('Clicked outside spider legs/cluster, unspiderifying and closing popup.');
                                            if (spiderifier) {
                                                spiderifier.unspiderfy();
                                            }
                                            if (currentPopup) {
                                                currentPopup.remove();
                                                currentPopup = null;
                                            }
                                            map.off('click', unspiderifyOnClickOutside); 
                                            if (unspiderifyOnMove) { 
                                               map.off('move', unspiderifyOnMove); 
                                            }
                                        } else {
                                            console.log('Clicked on spider leg or cluster, not unspiderifying via this handler.');
                                        }
                                    };
                                    map.on('click', unspiderifyOnClickOutside);

                                    unspiderifyOnMove = function () {
                                        console.log('Map moved, unspiderifying.');
                                        if (spiderifier) {
                                            spiderifier.unspiderfy();
                                        }
                                        if (currentPopup) { 
                                            currentPopup.remove();
                                            currentPopup = null;
                                        }
                                        map.off('move', unspiderifyOnMove); 
                                        if (unspiderifyOnClickOutside) { 
                                            map.off('click', unspiderifyOnClickOutside); 
                                        }
                                    };                                    map.once('move', unspiderifyOnMove);
                            } catch (error) {
                                console.error('Error applying spiderifier to cluster:', error);
                                fallbackToZoom();
                            }
                        } else {
                            fallbackToZoom();
                        }
                    }
                );

                // Helper function for fallback zoom behavior
                function fallbackToZoom() {
                    if (visualizationApplied) return; // Don't zoom if visualization was successfully applied

                    console.log('Falling back to cluster zoom behavior');
                    map.getSource('restaurants').getClusterExpansionZoom(
                        clusterId,
                        function (err, zoom) {
                            if (err) {
                                console.error('Error getting cluster expansion zoom:', err);
                                return;
                            }

                            // Zoom to the cluster with a slight zoom increase for better visibility
                            map.easeTo({
                                center: clusterCenter,
                                zoom: zoom + 0.5
                            });
                        }
                    );
                }
            });

            // Change cursor on cluster hover
            map.on('mouseenter', 'clusters', function () {
                map.getCanvas().style.cursor = 'pointer';
            });

            map.on('mouseleave', 'clusters', function () {
                map.getCanvas().style.cursor = '';
            });

            // Add individual points layer for non-clustered points
            map.addLayer({
                id: 'unclustered-point',
                type: 'circle',
                source: 'restaurants',
                filter: ['!', ['has', 'point_count']],
                paint: {
                    'circle-color': '#dc3545',
                    'circle-radius': 15,
                    'circle-stroke-width': 2,
                    'circle-stroke-color': '#fff'
                }
            });

            // Add number labels to individual points
            map.addLayer({
                id: 'unclustered-point-label',
                type: 'symbol',
                source: 'restaurants',
                filter: ['!', ['has', 'point_count']],
                layout: {
                    'text-field': ['get', 'number'],
                    'text-font': ['DIN Offc Pro Medium', 'Arial Unicode MS Bold'],
                    'text-size': 12
                },
                paint: {
                    'text-color': '#ffffff'
                }
            });

            // Handle clicks on individual points
            map.on('click', 'unclustered-point', function (e) {
                // Show popup for clicked point
                const features = map.queryRenderedFeatures(e.point, { layers: ['unclustered-point'] });
                if (!features.length) return;

                const feature = features[0];                // Close any existing popup
                if (currentPopup) {
                    currentPopup.remove();
                    currentPopup = null;
                }                // Create and display popup
                const popup = new mapboxgl.Popup({
                    closeButton: false,
                    closeOnClick: true,
                    className: 'restaurant-popup',
                    maxWidth: '300px'
                }).setLngLat(feature.geometry.coordinates)
                    .setHTML(feature.properties.popupContent)
                    .addTo(map);

                currentPopup = popup;
                
                // Record the time when popup was opened to prevent immediate closure
                lastPopupOpenedTime = Date.now();
            });            // Change cursor on point hover
            map.on('mouseenter', 'unclustered-point', function () {
                map.getCanvas().style.cursor = 'pointer';
            });

            map.on('mouseleave', 'unclustered-point', function () {
                map.getCanvas().style.cursor = '';
            });

            // Add map event listener for scatter functionality
            map.on('idle', function() {
                const currentZoom = map.getZoom();
                checkZoomForScatterView(currentZoom);
            });

            console.log('Map event listeners for scatter functionality added');
        }
    }
}

function createPopupContent(name, rating, reviewCount, address, id) {
    return `
        <div class="restaurant-popup" style="min-width: 200px;">
            <h6 class="mb-2 fw-bold">${name}</h6>
            <div class="d-flex align-items-center mb-2">
                <span class="text-warning me-1">★</span>
                <span class="fw-bold me-1">${rating}</span>
                <small class="text-muted">(${reviewCount} đánh giá)</small>
            </div>
            <p class="small text-muted mb-2">${address}</p>
            <div class="d-flex gap-2">
                <a href="/Restaurant/Details/${id}" class="btn btn-primary btn-sm">
                    Xem chi tiết
                </a>
            </div>
        </div>
    `;
}

function clearMarkers() {
    markers.forEach(({ marker, popup }) => {
        if (popup) popup.remove();
        if (marker) marker.remove();
    });
    markers = [];    if (currentPopup) {
        currentPopup.remove();
        currentPopup = null;
    }
    
    // Clear any scattered markers
    if (window.scatteredMarkers) {
        console.log('Clearing scattered markers from clearMarkers function');
        cleanupScatteredMarkers();
    }

    // Clean up spiderifier
    cleanupSpiderifier();
}

// Function to properly clean up the spiderifier
function cleanupSpiderifier() {
    // Clear any active spiderifier markers
    if (spiderifier) {
        try {
            console.log('Cleaning up spiderifier...');
            spiderifier.unspiderfy();
            
            // Note: We're not trying to remove specific event listeners here
            // as they're managed within each cluster click handler
        } catch (error) {
            console.warn('Error cleaning up spiderifier:', error);
        }
    }    // Also clean up any scattered markers
    if (window.scatteredMarkers) {
        console.log('Cleaning up scattered markers...');
        cleanupScatteredMarkers();
    }
}

// Helper function to clean up scattered marker popups specifically
function cleanupScatteredPopups() {
    console.log('Cleaning up scattered marker popups...');
    
    // Close tracked scattered popup
    if (currentPopup) {
        const popupElement = currentPopup.getElement();
        if (popupElement && popupElement.classList.contains('scattered-popup')) {
            console.log('Closing tracked scattered marker popup');
            currentPopup.remove();
            currentPopup = null;
        }
    }
    
    // Also clean up any untracked scattered popups
    const allScatteredPopups = document.querySelectorAll('.mapboxgl-popup.scattered-popup');
    if (allScatteredPopups.length > 0) {
        console.log(`Found ${allScatteredPopups.length} untracked scattered popups, removing them`);
        allScatteredPopups.forEach(popup => {
            try {
                const closeButton = popup.querySelector('.mapboxgl-popup-close-button');
                if (closeButton) {
                    closeButton.click();
                } else {
                    popup.remove();
                }
            } catch (error) {
                console.warn('Error removing scattered popup:', error);
            }
        });
    }
}
// Global handlers for spiderifier cleanup
function unspiderifyWhenClickingElsewhere(e) { 
    // Check if spiderifier is active by looking at its container
    const spideredContainer = document.querySelector('.spidered-marker-container');
    if (spideredContainer && spideredContainer.style.display === 'block') {
        // Check if the click isn't on a spider leg
        const spiderLegs = document.querySelectorAll('.spider-leg-pin');
        let clickedOnSpiderLeg = false;

        spiderLegs.forEach(leg => {
            if (e.originalEvent && e.originalEvent.target === leg) {
                clickedOnSpiderLeg = true;
            }
        });        if (!clickedOnSpiderLeg) {
            if (spiderifier) {
                spiderifier.unspiderfy();
                
                // Also close any open popup when clicking elsewhere
                if (currentPopup) {
                    currentPopup.remove();
                    currentPopup = null;
                }
                
                // Remove this event handler since we've handled the click
                map.off('click', unspiderifyWhenClickingElsewhere);
            }
        }
    }
}

function onMapMove() { 
    if (spiderifier) {
        spiderifier.unspiderfy();
    }
    
    // Also close any open popup on map movement
    if (currentPopup) {
        currentPopup.remove();
        currentPopup = null;
    }
}

// Reload map functionality
document.addEventListener('DOMContentLoaded', function () {
    const reloadButton = document.getElementById('reload-map-button');
    if (reloadButton) {
        reloadButton.addEventListener('click', function () {
            this.style.display = 'none';
            initializeMap();
        });
    }
});

// Handle window resize
window.addEventListener('resize', function () {
    if (map) {
        setTimeout(() => {
            map.resize();
        }, 100);
    }
});

// Function to focus map on a restaurant
function centerMapOnRestaurant(restaurantId) {
    const card = document.querySelector(`.restaurant-item[data-id="${restaurantId}"]`);
    if (!card || !map) {
        console.warn(`Card for restaurant ID ${restaurantId} not found or map not initialized`);
        return false;
    }

    // Unspiderify if needed
    if (spiderifier) {
        spiderifier.unspiderfy();
    }
    
    // Clean up any scattered markers
    cleanupScatteredMarkers();

    const lat = parseFloat(card.dataset.lat);
    const lng = parseFloat(card.dataset.lng);

    if (lat && lng && !isNaN(lat) && !isNaN(lng)) {
        console.log(`Centering map on restaurant: ${restaurantId} at (${lat}, ${lng})`);

        // Move map to restaurant location
        map.flyTo({
            center: [lng, lat],
            zoom: 16,
            duration: 1000
        });

        // Wait for map movement to complete before showing popup
        setTimeout(() => {
            // Close any existing popup
            if (currentPopup) {
                currentPopup.remove();
                currentPopup = null;
            }
              // Use data directly from the card instead of searching for features
            // as querySourceFeatures doesn't reliably find features in clusters
            const name = card.dataset.name;
            const rating = card.dataset.rating;
            const reviewCount = card.dataset.reviewCount;
            const address = card.dataset.address;
            
            console.log('Restaurant data from card dataset:', { 
                name: name, 
                rating: rating, 
                reviewCount: reviewCount, 
                address: address,
                allDataset: card.dataset 
            });
            
            // Always create a popup, with restaurant name from card or fallback
            const displayName = name || (' ' + restaurantId);
            const displayRating = rating || 'N/A';
            const displayReviewCount = reviewCount || '0';
            const displayAddress = address || '';              const popup = new mapboxgl.Popup({
                closeButton: false,
                closeOnClick: true,
                className: 'restaurant-popup',
                maxWidth: '300px'
            }).setLngLat([lng, lat])
                .setHTML(createPopupContent(
                    displayName,
                    displayRating,
                    displayReviewCount,
                    displayAddress,
                    restaurantId
                ))
                .addTo(map);
            
            currentPopup = popup;
            
            // Record the time when popup was opened to prevent immediate closure
            lastPopupOpenedTime = Date.now();
        }, 1200); // Wait a bit after the map animation

        return true;
    }

    return false;
}

// Initialize restaurant card handlers
function initializeRestaurantCardHandlers() {
    const restaurantCards = document.querySelectorAll('.restaurant-item');
    console.log('Finding restaurant cards to attach handlers...');

    restaurantCards.forEach(card => {
        // Get restaurant ID from card data attribute
        const restaurantId = card.dataset.id;
        if (!restaurantId) {
            console.warn('Restaurant card missing ID attribute:', card);
            return;
        }

        // Remove existing listeners to avoid duplicates
        const newCard = card.cloneNode(true);
        card.replaceWith(newCard);

        // Add click event to restaurant cards
        newCard.addEventListener('click', function (event) {
            // Only handle clicks on the card itself, not on links or buttons
            if (event.target.tagName.toLowerCase() === 'a' ||
                event.target.tagName.toLowerCase() === 'button') {
                return; // Let the link or button handle the click
            }

            const restaurantId = this.dataset.id;
            console.log(`Card clicked for restaurant ID: ${restaurantId}`);

            // Focus map on restaurant and show popup
            centerMapOnRestaurant(restaurantId);
        });
    });
    console.log('Restaurant card handlers initialized with', restaurantCards.length, 'cards');
}

// Initialize card handlers when page loads
document.addEventListener('DOMContentLoaded', function () {
    // Wait a bit for the map and features to be ready
    setTimeout(initializeRestaurantCardHandlers, 500);
});

// Global function to be called after AJAX updates
window.loadRestaurantsFromList = loadRestaurantsFromList;
window.centerMapOnRestaurant = centerMapOnRestaurant;
window.initializeRestaurantCardHandlers = initializeRestaurantCardHandlers;

// Track when the last popup was opened to prevent immediate closure
let lastPopupOpenedTime = 0;

// Check if we need to scatter markers based on current zoom level
function checkZoomForScatterView(zoomLevel) {
    console.log('=== CHECKING ZOOM FOR SCATTER VIEW ===');
    console.log('Current zoom level:', zoomLevel);
    console.log('Scatter threshold: 15');
    console.log('Current scatter state:', currentScatterState);
    console.log('Manual scatter active:', manualScatterActive);
    console.log('Scatter check in progress:', scatterCheckInProgress);
    
    // Prevent feedback loops
    if (scatterCheckInProgress) {
        console.log('Scatter check already in progress, skipping');
        return;
    }
    
    // Don't interfere with manual scattering
    if (manualScatterActive) {
        console.log('Manual scattering is active, automatic scattering disabled');
        return;
    }
    
    scatterCheckInProgress = true;
    
    try {
        // Determine desired state based on zoom level
        const desiredState = zoomLevel >= 15 ? 'scattered' : 'original';
        console.log('Desired state:', desiredState);
        
        // If we're already in the desired state, don't do anything
        if (currentScatterState === desiredState) {
            console.log('Already in desired state, no action needed');
            return;
        }
        
        if (zoomLevel >= 15) {
            console.log('Zoom level >= 15, checking for overlapping markers...');
            
            // Query all visible restaurant features (both clustered and unclustered)
            const unclusteredFeatures = map.queryRenderedFeatures({ layers: ['unclustered-point'] });
            const clusteredFeatures = map.queryRenderedFeatures({ layers: ['clusters'] });
            const allFeatures = [...unclusteredFeatures];
            
            console.log('Found unclustered features:', unclusteredFeatures.length);
            console.log('Found clustered features:', clusteredFeatures.length);
            console.log('Total features to check:', allFeatures.length);
              // Only proceed if we have unclustered features to work with (clustered features don't need scattering)
            if (allFeatures.length === 0) {
                console.log('No unclustered features found, keeping original markers visible');
                // Ensure original markers are visible if scattered markers were previously shown
                if (currentScatterState === 'scattered') {
                    // Close any existing popup before transitioning back to original
                    if (currentPopup) {
                        console.log('Closing existing popup before showing original markers');
                        currentPopup.remove();
                        currentPopup = null;
                    }
                    
                    cleanupScatteredMarkers();
                    showOriginalMarkers();
                    currentScatterState = 'original';
                }
                return;
            }
            
            // Use unclustered features for scattering logic
            const features = unclusteredFeatures;
            
            // Group nearby markers
            const groups = groupNearbyMarkers(features);
            console.log('Grouped markers into', groups.length, 'groups');
            
            // Check if any groups need scattering
            let needsScattering = false;
            groups.forEach((group) => {
                if (group.length > 1) {
                    needsScattering = true;
                }
            });
              if (needsScattering) {
                console.log('Found groups that need scattering, transitioning to scattered state');
                
                // Close any existing popup before hiding original markers
                if (currentPopup) {
                    console.log('Closing existing popup before scattering');
                    currentPopup.remove();
                    currentPopup = null;
                }
                
                // Only hide original markers if we actually need to scatter
                hideOriginalMarkers();
                currentScatterState = 'scattered';
                
                // Process each group that has multiple markers
                groups.forEach((group, groupIndex) => {
                    if (group.length > 1) {
                        console.log(`Group ${groupIndex + 1} has ${group.length} markers, scattering...`);
                        scatterMarkers(group, groupIndex);
                    } else {
                        console.log(`Group ${groupIndex + 1} has only 1 marker, skipping scatter`);
                    }
                });            } else {
                console.log('No groups need scattering, keeping original markers visible');                // Clean up any existing scattered markers and show originals
                if (currentScatterState === 'scattered') {
                    // Clean up scattered marker popups before transitioning back to original
                    cleanupScatteredPopups();
                    
                    cleanupScatteredMarkers();
                    showOriginalMarkers();
                    currentScatterState = 'original';
                }
            }        } else {            console.log('Zoom level < 15, transitioning to original state');
            if (currentScatterState === 'scattered') {
                // Clean up scattered marker popups before transitioning back to original
                cleanupScatteredPopups();
                
                cleanupScatteredMarkers();
                showOriginalMarkers();
                currentScatterState = 'original';
            }
        }} catch (error) {
        console.error('Error in checkZoomForScatterView:', error);
        // In case of error, ensure original markers are shown and scattered markers are cleaned up
        // Close any existing popup to prevent stale popups
        if (currentPopup) {
            console.log('Closing existing popup due to error in checkZoomForScatterView');
            currentPopup.remove();
            currentPopup = null;
        }
        
        cleanupScatteredMarkers();
        showOriginalMarkers();
        currentScatterState = 'original';
    } finally {
        // Always reset the flag to prevent infinite loops
        scatterCheckInProgress = false;
        console.log('Scatter check completed, flag reset, current state:', currentScatterState);
    }
}

// Hide original marker layers when scattering
function hideOriginalMarkers() {
    console.log('=== HIDING ORIGINAL MARKERS ===');
    
    try {
        // Hide unclustered points
        if (map.getLayer('unclustered-point')) {
            map.setLayoutProperty('unclustered-point', 'visibility', 'none');
            console.log('Hidden unclustered-point layer');
        }
        
        // Hide unclustered point labels
        if (map.getLayer('unclustered-point-label')) {
            map.setLayoutProperty('unclustered-point-label', 'visibility', 'none');
            console.log('Hidden unclustered-point-label layer');
        }
        
        // Hide clusters
        if (map.getLayer('clusters')) {
            map.setLayoutProperty('clusters', 'visibility', 'none');
            console.log('Hidden clusters layer');
        }
        
        // Hide cluster count labels
        if (map.getLayer('cluster-count')) {
            map.setLayoutProperty('cluster-count', 'visibility', 'none');
            console.log('Hidden cluster-count layer');
        }
    } catch (error) {
        console.error('Error hiding original markers:', error);
    }
}

// Show original marker layers when not scattering
function showOriginalMarkers() {
    console.log('=== SHOWING ORIGINAL MARKERS ===');
    
    try {
        // Show unclustered points
        if (map.getLayer('unclustered-point')) {
            map.setLayoutProperty('unclustered-point', 'visibility', 'visible');
            console.log('Shown unclustered-point layer');
        }
        
        // Show unclustered point labels
        if (map.getLayer('unclustered-point-label')) {
            map.setLayoutProperty('unclustered-point-label', 'visibility', 'visible');
            console.log('Shown unclustered-point-label layer');
        }
        
        // Show clusters
        if (map.getLayer('clusters')) {
            map.setLayoutProperty('clusters', 'visibility', 'visible');
            console.log('Shown clusters layer');
        }
        
        // Show cluster count labels
        if (map.getLayer('cluster-count')) {
            map.setLayoutProperty('cluster-count', 'visibility', 'visible');
            console.log('Shown cluster-count layer');
        }
          // Reset all scatter-related flags
        scatteredMarkersActive = false;
        manualScatterActive = false; // Reset manual scatter flag when showing original markers
        
        // Verify cluster click handlers are still active after showing original markers
        setTimeout(() => {
            ensureClusterClickHandlers();
        }, 100);
        
    } catch (error) {
        console.error('Error showing original markers:', error);
    }
}

// Group nearby markers that should be scattered
function groupNearbyMarkers(features, radiusPixels = 50) {
    console.log('=== GROUPING NEARBY MARKERS ===');
    console.log('Input features:', features.length);
    console.log('Radius pixels:', radiusPixels);
    
    // Debug: Log what we're getting as input
    features.forEach((feature, index) => {
        console.log(`Input feature ${index}:`, {
            type: typeof feature,
            hasGeometry: !!(feature && feature.geometry),
            hasCoordinates: !!(feature && feature.geometry && feature.geometry.coordinates),
            coordinates: feature && feature.geometry ? feature.geometry.coordinates : 'none'
        });
    });
    
    const groups = [];
    const processed = new Set();
    
    features.forEach((feature, index) => {
        if (processed.has(index)) {
            console.log(`Feature ${index} already processed, skipping`);
            return;
        }
        
        // Validate feature structure before processing
        if (!feature || !feature.geometry || !feature.geometry.coordinates) {
            console.error(`Feature ${index} has invalid structure, skipping:`, feature);
            return;
        }
        
        let featurePoint;
        try {
            featurePoint = map.project(feature.geometry.coordinates);
            console.log(`Feature ${index} screen position:`, featurePoint);
        } catch (error) {
            console.error(`Error projecting feature ${index}:`, error, feature);
            return;
        }
        
        const group = [feature];
        processed.add(index);
        
        // Find nearby features
        features.forEach((otherFeature, otherIndex) => {
            if (otherIndex !== index && !processed.has(otherIndex)) {
                // Validate other feature structure
                if (!otherFeature || !otherFeature.geometry || !otherFeature.geometry.coordinates) {
                    console.error(`Other feature ${otherIndex} has invalid structure, skipping:`, otherFeature);
                    return;
                }
                
                let otherPoint;
                try {
                    otherPoint = map.project(otherFeature.geometry.coordinates);
                } catch (error) {
                    console.error(`Error projecting other feature ${otherIndex}:`, error, otherFeature);
                    return;
                }
                
                const distance = Math.sqrt(
                    Math.pow(featurePoint.x - otherPoint.x, 2) + 
                    Math.pow(featurePoint.y - otherPoint.y, 2)
                );
                
                console.log(`Distance between feature ${index} and ${otherIndex}:`, distance);
                
                if (distance < radiusPixels) {
                    console.log(`Feature ${otherIndex} is within radius, adding to group`);
                    group.push(otherFeature);
                    processed.add(otherIndex);
                }
            }
        });
        
        console.log(`Group created with ${group.length} features`);
        groups.push(group);
    });
    
    console.log('Final groups:', groups.length);
    return groups;
}

// Calculate center point for a group of markers
function calculateGroupCenter(group) {
    console.log('=== CALCULATING GROUP CENTER ===');
    console.log('Group size:', group.length);
    
    if (group.length === 0) {
        console.error('Empty group provided to calculateGroupCenter');
        return null;
    }
    
    let totalLng = 0;
    let totalLat = 0;
    let validCount = 0;
    
    group.forEach((feature, index) => {
        let coords = null;
        
        // Debug: log what we're actually getting
        console.log(`Feature ${index} type:`, typeof feature);
        console.log(`Feature ${index} structure:`, feature);
        
        // Handle case where feature might be a primitive (number) - this shouldn't happen but let's be safe
        if (typeof feature === 'number') {
            console.error(`Feature ${index} is a number (${feature}) instead of an object - this indicates a bug in grouping logic`);
            return; // Skip this iteration
        }
        
        // Handle case where feature might be an array [lng, lat]
        if (Array.isArray(feature) && feature.length >= 2 && typeof feature[0] === 'number' && typeof feature[1] === 'number') {
            console.log(`Feature ${index} appears to be a coordinate array:`, feature);
            coords = feature;
        }
        // Normal GeoJSON feature structure
        else if (feature && feature.geometry && feature.geometry.coordinates) {
            coords = feature.geometry.coordinates;
        } 
        // Direct coordinates property
        else if (feature && feature.coordinates) {
            coords = feature.coordinates;
        } 
        // Mapbox marker object
        else if (feature && typeof feature.getLngLat === 'function') {
            const lngLat = feature.getLngLat();
            coords = [lngLat.lng, lngLat.lat];
        }
        // Try properties if it's a malformed feature
        else if (feature && feature.properties && feature.properties.coordinates) {
            coords = feature.properties.coordinates;
        }
        else {
            console.error(`Feature ${index} structure unrecognized:`, feature);
        }
        
        if (coords && Array.isArray(coords) && coords.length >= 2 && typeof coords[0] === 'number' && typeof coords[1] === 'number') {
            console.log(`Feature ${index} coords:`, coords);
            totalLng += coords[0];
            totalLat += coords[1];
            validCount++;
        } else {
            console.error(`Feature ${index} has invalid coordinates:`, coords);
        }
    });
    
    if (validCount === 0) {
        console.error('No valid coordinates found in group');
        return null;
    }
    
    const centerLng = totalLng / validCount;
    const centerLat = totalLat / validCount;
    
    console.log('Calculated center:', { lng: centerLng, lat: centerLat });
    return [centerLng, centerLat];
}

// Scatter markers around their center point, using techniques from mapboxgl-spiderifier
function scatterMarkers(group, groupIndex) {
    console.log('=== SCATTERING MARKERS ===');
    console.log(`Group ${groupIndex + 1}:`, group.length, 'markers');
    
    // Set the flag that we're showing scattered markers
    scatteredMarkersActive = true;
    
    // Calculate group center
    const center = calculateGroupCenter(group);
    if (!center) {
        console.error('Could not calculate center for group', groupIndex);
        return;
    }
    
    console.log('Group center coordinates:', center);
    
    // Create a LngLat object for the center
    const centerLngLat = new mapboxgl.LngLat(center[0], center[1]);
    
    // Project center to pixel coordinates - this is critical for accurate positioning
    const centerPoint = map.project(centerLngLat);
    console.log('Center point in pixels:', centerPoint);
    
    // Initialize scattered markers array if it doesn't exist
    if (!window.scatteredMarkers) {
        window.scatteredMarkers = [];
        console.log('Initialized scatteredMarkers array');
    }
    
    // Create DOM container for scattered markers if it doesn't exist
    let scatteredContainer = document.getElementById('scattered-markers-container');
    if (!scatteredContainer) {
        scatteredContainer = document.createElement('DIV');
        scatteredContainer.id = 'scattered-markers-container';
        scatteredContainer.style.position = 'absolute';
        scatteredContainer.style.pointerEvents = 'none';
        scatteredContainer.style.zIndex = '1000';
        scatteredContainer.style.width = '100%';
        scatteredContainer.style.height = '100%';
        scatteredContainer.style.top = '0';
        scatteredContainer.style.left = '0';
        map.getContainer().appendChild(scatteredContainer);
    }
    
    // Calculate positions using a circle arrangement or spiral for many points
    const positions = calculateScatterPositions(group.length);
    console.log('Calculated scatter positions:', positions);
    
    group.forEach((feature, index) => {
        console.log(`\n--- Processing marker ${index + 1}/${group.length} ---`);
        console.log('Original feature coordinates:', feature.geometry.coordinates);
        
        const pos = positions[index];
        console.log('Position for this marker:', pos);
        
        // Create marker element with styling similar to spiderifier legs
        const markerEl = document.createElement('div');
        markerEl.className = 'scattered-marker';
        markerEl.setAttribute('data-feature-id', feature.properties.id || index);
        
        // Style the marker with explicit CSS similar to spider legs
        markerEl.style.position = 'absolute';
        markerEl.style.width = '36px';
        markerEl.style.height = '36px';
        markerEl.style.backgroundColor = '#dc3545';
        markerEl.style.border = '3px solid white';
        markerEl.style.borderRadius = '50%';
        markerEl.style.display = 'flex';
        markerEl.style.alignItems = 'center';
        markerEl.style.justifyContent = 'center';
        markerEl.style.color = 'white';
        markerEl.style.fontWeight = 'bold';
        markerEl.style.fontSize = '14px';
        markerEl.style.boxShadow = '0 4px 8px rgba(0,0,0,0.4)';
        markerEl.style.cursor = 'pointer';
        markerEl.style.zIndex = '1000';
        markerEl.style.pointerEvents = 'auto'; // Allow clicks
        
        // Add marker number/identifier
        if (feature.properties.index) {
            markerEl.textContent = feature.properties.index;
        } else if (feature.properties.number) {
            markerEl.textContent = feature.properties.number;
        } else {
            markerEl.textContent = (index + 1).toString();
        }
        
        // Calculate the visual position in pixels - using same method as spiderifier
        const markerPixelX = centerPoint.x + pos.x;
        const markerPixelY = centerPoint.y + pos.y;
        
        // Center the marker by accounting for its size
        const markerSize = 36; // Size in pixels (matching the CSS)
        const halfSize = markerSize / 2;
        
        // Position the marker using absolute positioning
        markerEl.style.left = `${markerPixelX - halfSize}px`;
        markerEl.style.top = `${markerPixelY - halfSize}px`;
        
        // Calculate the actual geographic coordinates by unprojecting the pixel position
        const visualPoint = {
            x: markerPixelX,
            y: markerPixelY
        };
        
        // Convert pixel position back to geographic coordinates
        let visualLngLat;
        try {
            visualLngLat = map.unproject(visualPoint);
            console.log('Visual LngLat for marker:', visualLngLat);
            
            // Store coordinates as data attributes for later use
            markerEl.setAttribute('data-lng', visualLngLat.lng);
            markerEl.setAttribute('data-lat', visualLngLat.lat);
            markerEl.setAttribute('data-original-lng', feature.geometry.coordinates[0]);
            markerEl.setAttribute('data-original-lat', feature.geometry.coordinates[1]);
        } catch (error) {
            console.error('Error unprojecting coordinates:', error);
            visualLngLat = {
                lng: feature.geometry.coordinates[0],
                lat: feature.geometry.coordinates[1]
            };
        }
        
        // Add click handler for popup
        markerEl.addEventListener('click', function(e) {
            e.stopPropagation();
            console.log('Scattered marker clicked:', feature.properties);
            
            // Close existing popup
            if (currentPopup) {
                currentPopup.remove();
            }
            
            // Get the coordinates from data attributes
            const lng = parseFloat(markerEl.getAttribute('data-lng') || visualLngLat.lng);
            const lat = parseFloat(markerEl.getAttribute('data-lat') || visualLngLat.lat);            // Create popup at the marker's position
            const popup = new mapboxgl.Popup({
                closeButton: false,
                closeOnClick: true,
                className: 'scattered-popup', // This class helps us identify popups from scattered markers
                maxWidth: '300px',
                offset: [0, -18], // Offset above the marker
                anchor: 'bottom'
            })
            .setHTML(feature.properties.popupContent)
            .setLngLat([lng, lat]) // Use visual coordinates for popup
            .addTo(map);
              currentPopup = popup;
            lastPopupOpenedTime = Date.now();
            
            console.log('Scattered marker popup created with high z-index at position:', [lng, lat]);
        });
        
        // Add hover effect
        markerEl.addEventListener('mouseenter', function() {
            this.style.transform = 'scale(1.1)';
        });
        
        markerEl.addEventListener('mouseleave', function() {
            this.style.transform = 'scale(1)';
        });
        
        // Add to the container
        scatteredContainer.appendChild(markerEl);
        
        // Store reference with additional info
        const markerInfo = {
            element: markerEl,
            originalCoords: feature.geometry.coordinates,
            visualCoords: [visualLngLat.lng, visualLngLat.lat],
            pixelPosition: visualPoint,
            feature: feature,
            remove: function() {
                if (markerEl.parentNode) {
                    markerEl.parentNode.removeChild(markerEl);
                }
            }
        };
        
        window.scatteredMarkers.push(markerInfo);
        console.log('Added scattered marker:', markerInfo.visualCoords);
    });
    
    // Make the container visible
    scatteredContainer.style.display = 'block';
    
    console.log(`Finished scattering group ${groupIndex + 1}`);
    console.log('Total scattered markers:', window.scatteredMarkers.length);
    
    // Update positions when map moves or zooms
    map.on('move', updateScatteredMarkers);
    map.on('zoom', updateScatteredMarkers);
    
    return true;
}

// Update positions of scattered markers when map moves
function updateScatteredMarkers() {
    if (!window.scatteredMarkers || window.scatteredMarkers.length === 0) return;
    
    const container = document.getElementById('scattered-markers-container');
    if (!container) return;
    
    window.scatteredMarkers.forEach(markerInfo => {
        if (!markerInfo.originalCoords) return;
        
        // Get the center coordinates for this marker's group
        // For now we'll use the original coordinates as a reference point
        const centerLngLat = new mapboxgl.LngLat(
            markerInfo.originalCoords[0], 
            markerInfo.originalCoords[1]
        );
        
        // Project center to new pixel position
        const centerPoint = map.project(centerLngLat);
        
        // Get the offset from the original calculation
        const offsetX = markerInfo.pixelPosition.x - centerPoint.x;
        const offsetY = markerInfo.pixelPosition.y - centerPoint.y;
        
        // Calculate new pixel position
        const newPixelX = centerPoint.x + offsetX;
        const newPixelY = centerPoint.y + offsetY;
        
        // Update the element position
        const markerEl = markerInfo.element;
        if (markerEl) {
            const markerSize = 36; // Match the CSS size
            const halfSize = markerSize / 2;
            
            markerEl.style.left = `${newPixelX - halfSize}px`;
            markerEl.style.top = `${newPixelY - halfSize}px`;
        }
    });
}

// Calculate positions for scattered markers based on count
function calculateScatterPositions(count) {
    const positions = [];
    
    if (count <= 0) return positions;
      // If only one marker, position it above the center
    if (count === 1) {
        positions.push({
            angle: 0,
            leg: 40 // Further reduced from 60px to 40px above
        });
        return positions;
    }
    
    // Use a spiral for many points (more than 8)
    if (count > 8) {
        let legLength = 30; // Further reduced starting length (from 40px to 30px)
        const angleStep = Math.PI * 2 / 30; // Smaller step = more tightly packed spiral
        
        // Start angle slightly offset to avoid direct vertical alignment
        let angle = Math.PI / 6;
        
        for (let i = 0; i < count; i++) {
            positions.push({
                angle: angle,
                leg: legLength,
                x: legLength * Math.cos(angle),
                y: legLength * Math.sin(angle)
            });
            angle += angleStep;
            legLength += 2; // Further reduced increment (from 3px to 2px) for tighter spiral
        }
        
        return positions;
    }
    
    // For 2-8 markers, use a circle arrangement
    const radius = 15;
    const angleStep = (Math.PI * 2) / count;
    
    // Start angle slightly offset to avoid direct vertical alignment
    let angle = Math.PI / 6;
    
    for (let i = 0; i < count; i++) {
        positions.push({
            angle: angle,
            leg: radius,
            x: radius * Math.cos(angle),
            y: radius * Math.sin(angle)
        });
        angle += angleStep;
    }
    
    return positions;
}

// Clean up scattered markers
function cleanupScatteredMarkers() {
    console.log('=== CLEANING UP SCATTERED MARKERS ===');
    
    // Store whether markers were active before resetting flag
    const wereMarkersActive = scatteredMarkersActive;
    
    // Reset all scatter-related flags
    scatteredMarkersActive = false;
    manualScatterActive = false; // Reset manual scatter flag
    
    // Remove event listeners for map movement
    map.off('move', updateScatteredMarkers);
    map.off('zoom', updateScatteredMarkers);
    
    // Clean up container
    const container = document.getElementById('scattered-markers-container');
    if (container) {
        container.style.display = 'none';
        
        // Remove all marker elements
        while (container.firstChild) {
            container.removeChild(container.firstChild);
        }
    }
      if (window.scatteredMarkers && window.scatteredMarkers.length > 0) {
        console.log('Removing', window.scatteredMarkers.length, 'scattered markers');
        
        window.scatteredMarkers.forEach((markerInfo, index) => {
            try {
                // Check what kind of marker object we have
                if (markerInfo.remove && typeof markerInfo.remove === 'function') {
                    // New style marker with remove method
                    markerInfo.remove();
                } else if (markerInfo.element) {
                    // DOM element style marker
                    if (markerInfo.element.parentNode) {
                        markerInfo.element.parentNode.removeChild(markerInfo.element);
                    }
                } else if (markerInfo.marker && markerInfo.marker.remove) {
                    // Old style mapbox marker
                    markerInfo.marker.remove();
                } else {
                    // Fallback for old style
                    const marker = markerInfo.marker || markerInfo;
                    if (marker && marker.remove) {
                        marker.remove();
                    }                }
                console.log(`Removed scattered marker ${index + 1}`);
            } catch (error) {
                console.error(`Error removing scattered marker ${index + 1}:`, error);
            }
        });
        
        window.scatteredMarkers = [];
        console.log('Scattered markers array cleared');
    }
    
    console.log('Scattered markers cleanup complete');
}

// Manual testing function for debugging
function testScatterMarkers() {
    console.log('=== MANUAL SCATTER TEST ===');
    
    if (!map) {
        console.error('Map not initialized');
        return;
    }
    
    const currentZoom = map.getZoom();
    console.log('Current zoom for test:', currentZoom);
    
    // Force check scatter view
    checkZoomForScatterView(currentZoom);
}

// Make test function globally available
window.testScatterMarkers = testScatterMarkers;

// Utility function to ensure cluster click handlers remain active
function ensureClusterClickHandlers() {
    // This function helps debug cluster click functionality
    // if it gets lost during zoom transitions
    
    console.log('=== ENSURING CLUSTER CLICK HANDLERS ===');
    
    if (!map || !map.getLayer('clusters')) {
        console.log('No clusters layer found, handlers not needed');
        return false;
    }
    
    try {
        // Query for any clusters on the map to test if they're responsive
        const clusteredFeatures = map.queryRenderedFeatures({ layers: ['clusters'] });
        console.log(`Found ${clusteredFeatures.length} cluster features on map`);
        
        if (clusteredFeatures.length > 0) {
            console.log('Clusters are present, cluster handlers should be active from loadRestaurantsFromList');
            return true;
        } else {
            console.log('No clusters currently visible');
            return false;
        }
    } catch (error) {
        console.error('Error ensuring cluster handlers:', error);
        return false;
    }
}
