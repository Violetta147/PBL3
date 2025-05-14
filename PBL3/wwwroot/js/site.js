// Please see documentation at https://learn.microsoft.com/aspnet/core/client-side/bundling-and-minification
// for details on configuring this project to bundle and minify static web assets.

// Write your JavaScript code.

// Custom Leaflet icon classes
var LeafIcon = L.Icon.extend({
    options: {
        shadowUrl: '/images/leaf-shadow.png',
        iconSize: [38, 95],
        shadowSize: [50, 64],
        iconAnchor: [22, 94],
        shadowAnchor: [4, 62],
        popupAnchor: [-3, -76]
    }
});

// Create icon instances
var greenIcon = new LeafIcon({ iconUrl: '/images/leaf-green.png' });
var redIcon = new LeafIcon({ iconUrl: '/images/leaf-red.png' });
var orangeIcon = new LeafIcon({ iconUrl: '/images/leaf-orange.png' });