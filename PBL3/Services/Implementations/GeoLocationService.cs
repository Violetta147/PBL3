using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using PBL3.Services.Interfaces;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Globalization;

namespace PBL3.Services.Implementations
{
    public class GeoLocationService : IGeoLocationService
    {
        private readonly HttpClient _httpClient;
        private readonly string _mapboxAccessToken;
        private readonly ILogger<GeoLocationService> _logger;
        private readonly string _sessionToken; // Session token for Mapbox SearchBox API
        
        // Vietnam bounding box - limiting results to this geographical region
        private readonly double[] _vietnamBBox = { 102.0, 8.0, 110.0, 24.0 }; // [west, south, east, north]
        
        // Dictionary of major Vietnamese cities for direct matching
        private readonly Dictionary<string, (double lat, double lng)> _vietnameseCities;

        public GeoLocationService(HttpClient httpClient, IConfiguration configuration, ILogger<GeoLocationService> logger)
        {
            _httpClient = httpClient;
            _mapboxAccessToken = configuration["Mapbox:AccessToken"] ?? 
                throw new InvalidOperationException("Mapbox:AccessToken is not configured in app settings");
            _logger = logger;
            
            // Generate a random session token that will persist for the lifetime of this service instance
            _sessionToken = Guid.NewGuid().ToString();
            _logger.LogInformation("Created Mapbox session token: {SessionToken}", _sessionToken);
            
            // Initialize dictionary of major Vietnamese cities with their coordinates
            _vietnameseCities = new Dictionary<string, (double lat, double lng)>(StringComparer.OrdinalIgnoreCase)
            {
                { "Hà Nội", (21.0278, 105.8342) },
                { "Hanoi", (21.0278, 105.8342) },
                { "Hồ Chí Minh", (10.8231, 106.6297) },
                { "Ho Chi Minh", (10.8231, 106.6297) },
                { "Saigon", (10.8231, 106.6297) },
                { "Sài Gòn", (10.8231, 106.6297) },
                { "Đà Nẵng", (16.0544, 108.2022) },
                { "Da Nang", (16.0544, 108.2022) },
                { "Hải Phòng", (20.8449, 106.6881) },
                { "Hai Phong", (20.8449, 106.6881) },
                { "Cần Thơ", (10.0452, 105.7469) },
                { "Can Tho", (10.0452, 105.7469) },
                { "Huế", (16.4637, 107.5909) },
                { "Hue", (16.4637, 107.5909) },
                { "Nha Trang", (12.2388, 109.1968) },
                { "Đà Lạt", (11.9404, 108.4583) },
                { "Da Lat", (11.9404, 108.4583) },
                { "Vũng Tàu", (10.3460, 107.0843) },
                { "Vung Tau", (10.3460, 107.0843) },
                { "Buôn Ma Thuột", (12.6789, 108.0389) },
                { "Buon Ma Thuot", (12.6789, 108.0389) }
            };
        }
        
        public async Task<(double latitude, double longitude)> GetCoordinatesFromAddressAsync(string address)
        {
            if (string.IsNullOrWhiteSpace(address))
            {
                _logger.LogWarning("Empty address provided to GetCoordinatesFromAddressAsync");
                // Default coordinates for Da Nang
                return (16.047079, 108.206230);
            }
            
            // Check if this is likely a detailed street address (e.g., starting with a number)
            bool isDetailedAddress = IsLikelyStreetAddress(address);
            
            _logger.LogInformation("Processing address: {Address}, Detected as detailed: {IsDetailed}", 
                address, isDetailedAddress);
            
            // For city searches, try direct matching first
            if (!isDetailedAddress && TryDirectCityMatch(address, out var coordinates))
            {
                _logger.LogInformation("Direct city match found for: {Address}", address);
                return coordinates;
            }

            try
            {
                // Format the bounding box string: west,south,east,north
                string bboxString = string.Join(",", _vietnamBBox);
                
                // For detailed street addresses, use the Geocoding API directly
                if (isDetailedAddress)
                {
                    // Use Geocoding API for detailed addresses
                    var geocodingUrl = $"https://api.mapbox.com/geocoding/v5/mapbox.places/{Uri.EscapeDataString(address)}.json" +
                        $"?access_token={_mapboxAccessToken}" +
                        $"&country=vn" + // Limit results to Vietnam
                        $"&bbox={bboxString}" + // Use Vietnam bounding box
                        $"&language=vi" + // Prefer Vietnamese results
                        $"&limit=5" + // Get fewer but more relevant results                        $"&types=address,place" + // Focus on addresses and places
                        $"&autocomplete=false"; // Complete search for exact address matching
                    
                    _logger.LogInformation("Using Geocoding API for detailed address: {Address}", address);
                    
                    var geocodingResponse = await _httpClient.GetAsync(geocodingUrl);
                    
                    if (geocodingResponse.IsSuccessStatusCode)
                    {
                        var geocodingContent = await geocodingResponse.Content.ReadAsStringAsync();                        var geocodingData = JsonDocument.Parse(geocodingContent);
                        
                        var geocodingFeatures = geocodingData.RootElement.GetProperty("features").EnumerateArray().ToList();
                        
                        if (geocodingFeatures.Count > 0)
                        {
                            // Extract coordinates from the first (most relevant) feature
                            var center = geocodingFeatures[0].GetProperty("center").EnumerateArray().ToArray();
                            
                            // Mapbox returns coordinates as [longitude, latitude]
                            double lng = center.Length > 0 ? center[0].GetDouble() : 108.206230;
                            double lat = center.Length > 1 ? center[1].GetDouble() : 16.047079;
                            
                            _logger.LogInformation("Successfully geocoded detailed address: {Address} to ({Lat}, {Lng})", 
                                address, lat, lng);
                            
                            return (lat, lng);
                        }
                    }
                    
                    _logger.LogWarning("Geocoding API failed for detailed address, falling back to SearchBox API");
                }
                
                // For non-detailed addresses or if Geocoding API failed, use SearchBox API
                var suggestUrl = $"https://api.mapbox.com/search/searchbox/v1/suggest" +
                    $"?q={Uri.EscapeDataString(address)}" +
                    $"&session_token={_sessionToken}" +
                    $"&access_token={_mapboxAccessToken}" +
                    $"&country=vn" + // Limit results to Vietnam
                    $"&bbox={bboxString}" + // Use Vietnam bounding box
                    $"&language=vi" + // Prefer Vietnamese results
                    $"&limit=10" + // Increase result limit to find better matches
                    $"&types=region,district,place,locality,neighborhood,address"; // Focus on administrative divisions
                
                _logger.LogInformation("Using suggest URL with Vietnamese parameters: {Url}", suggestUrl);
                
                var suggestResponse = await _httpClient.GetAsync(suggestUrl);
                
                // Check for failure and add debug breakpoint
                if (!suggestResponse.IsSuccessStatusCode)
                {
                    var errorContent = await suggestResponse.Content.ReadAsStringAsync();
                    _logger.LogError("Mapbox API call failed with status: {Status}, Response: {Response}", 
                        suggestResponse.StatusCode, errorContent);
                    
                    // When debugging is enabled, stop execution here
                    System.Diagnostics.Debugger.Break();
                }
                
                suggestResponse.EnsureSuccessStatusCode();

                var suggestContent = await suggestResponse.Content.ReadAsStringAsync();
                var suggestData = JsonDocument.Parse(suggestContent);

                // Check if we have suggestions
                var suggestions = suggestData.RootElement.GetProperty("suggestions").EnumerateArray().ToList();
                
                if (suggestions.Count == 0)
                {
                    _logger.LogWarning("No suggestions found for address: {Address}", address);
                    // Default coordinates for Da Nang
                    return (16.047079, 108.206230);
                }

                // Find the most relevant suggestion by doing additional matching
                // Try to find exact matches in name or matching the city name
                var bestSuggestion = FindBestVietnameseMatch(suggestions, address);
                
                string id = bestSuggestion.GetProperty("mapbox_id").GetString() ?? 
                    throw new InvalidOperationException("Could not get mapbox_id from suggestion");
                
                // Log which suggestion was selected
                _logger.LogInformation("Selected suggestion: {Name} with ID: {Id}", 
                    bestSuggestion.TryGetProperty("name", out var nameElement) ? nameElement.GetString() : "unknown",
                    id);

                // Step 2: Call the retrieve endpoint to get details
                var retrieveUrl = $"https://api.mapbox.com/search/searchbox/v1/retrieve/{id}?session_token={_sessionToken}&access_token={_mapboxAccessToken}";
                _logger.LogInformation("Retrieve request URL: {Url}", retrieveUrl);
                
                var retrieveResponse = await _httpClient.GetAsync(retrieveUrl);
                
                // Check for failure and add debug breakpoint
                if (!retrieveResponse.IsSuccessStatusCode)
                {
                    var errorContent = await retrieveResponse.Content.ReadAsStringAsync();
                    _logger.LogError("Mapbox retrieve API call failed with status: {Status}, Response: {Response}", 
                        retrieveResponse.StatusCode, errorContent);
                    
                    // When debugging is enabled, stop execution here
                    System.Diagnostics.Debugger.Break();
                }
                
                retrieveResponse.EnsureSuccessStatusCode();

                var retrieveContent = await retrieveResponse.Content.ReadAsStringAsync();
                var retrieveData = JsonDocument.Parse(retrieveContent);
                
                // Extract coordinates from the first feature
                var features = retrieveData.RootElement.GetProperty("features").EnumerateArray();
                
                if (!features.MoveNext())
                {
                    _logger.LogWarning("No features found for suggestion ID: {Id}", id);
                    // Default coordinates for Da Nang
                    return (16.047079, 108.206230);
                }
                
                var coordinateArray = features.Current.GetProperty("geometry").GetProperty("coordinates").EnumerateArray();
                
                // Mapbox returns coordinates as [longitude, latitude]
                var longitude = coordinateArray.MoveNext() ? coordinateArray.Current.GetDouble() : 108.206230;
                var latitude = coordinateArray.MoveNext() ? coordinateArray.Current.GetDouble() : 16.047079;

                _logger.LogInformation("Successfully geocoded address: {Address} to coordinates: ({Lat}, {Lng})", 
                    address, latitude, longitude);
                
                return (latitude, longitude);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error geocoding address: {Address}", address);
                
                // When debugging is enabled, stop execution here
                System.Diagnostics.Debugger.Break();
                
                // Default coordinates for Da Nang
                return (16.047079, 108.206230);
            }
        }
        
        /// <summary>
        /// Determines if an address is likely a detailed street address
        /// </summary>
        private bool IsLikelyStreetAddress(string address)
        {
            if (string.IsNullOrWhiteSpace(address))
                return false;
                
            // Check for number at the beginning (like "19 Đ.")
            if (char.IsDigit(address[0]))
                return true;
                
            // Check for common street indicators in Vietnamese
            string[] streetIndicators = { "đường", "duong", "đ.", "d.", "phố", "pho", "ngõ", "ngo", "ngách", "ngach", "hẻm", "hem" };
            foreach (var indicator in streetIndicators)
            {
                if (address.ToLower().Contains(indicator))
                    return true;
            }
            
            // Check for commas indicating multiple address parts
            int commaCount = address.Count(c => c == ',');
            if (commaCount >= 2) // At least street, ward, district
                return true;
                
            return false;
        }
        
        /// <summary>
        /// Try to directly match the address to known Vietnamese cities.
        /// </summary>
        private bool TryDirectCityMatch(string address, out (double lat, double lng) coordinates)
        {
            // For city searches, try to directly match from our dictionary of major cities
            address = address.Trim();
            
            // Try an exact match first
            if (_vietnameseCities.TryGetValue(address, out coordinates))
            {
                return true;
            }
            
            // Check if the address starts with a city name
            foreach (var city in _vietnameseCities.Keys)
            {
                if (address.StartsWith(city, StringComparison.OrdinalIgnoreCase) || 
                    address.EndsWith(city, StringComparison.OrdinalIgnoreCase))
                {
                    coordinates = _vietnameseCities[city];
                    return true;
                }
            }
            
            // Check if address contains a city name (less precise but useful for district queries)
            foreach (var city in _vietnameseCities.Keys)
            {
                if (address.Contains(city, StringComparison.OrdinalIgnoreCase))
                {
                    coordinates = _vietnameseCities[city];
                    return true;
                }
            }
            
            coordinates = (16.047079, 108.206230); // Default to Da Nang
            return false;
        }
        
        /// <summary>
        /// Find the best match from a list of suggestions for a Vietnamese address
        /// </summary>
        private JsonElement FindBestVietnameseMatch(List<JsonElement> suggestions, string address)
        {
            // Try various strategies to find the most relevant suggestion
            
            // 1. First try exact name match
            foreach (var suggestion in suggestions)
            {
                if (suggestion.TryGetProperty("name", out var nameElement) && 
                    string.Equals(nameElement.GetString(), address, StringComparison.OrdinalIgnoreCase))
                {
                    return suggestion;
                }
            }
            
            // 2. Try contains match with city name for each suggestion
            foreach (var cityName in _vietnameseCities.Keys)
            {
                if (address.Contains(cityName, StringComparison.OrdinalIgnoreCase))
                {
                    foreach (var suggestion in suggestions)
                    {
                        if (suggestion.TryGetProperty("name", out var nameElement) && 
                            nameElement.GetString()?.Contains(cityName, StringComparison.OrdinalIgnoreCase) == true)
                        {
                            return suggestion;
                        }
                    }
                }
            }
            
            // 3. Check for place_formatted match containing the address
            foreach (var suggestion in suggestions)
            {
                if (suggestion.TryGetProperty("place_formatted", out var placeElement))
                {
                    string? placeFormatted = placeElement.GetString();
                    if (!string.IsNullOrEmpty(placeFormatted) && 
                        (placeFormatted.Contains(address, StringComparison.OrdinalIgnoreCase) ||
                         address.Contains(placeFormatted, StringComparison.OrdinalIgnoreCase)))
                    {
                        return suggestion;
                    }
                }
            }
            
            // 4. Check country to ensure we're only getting results from Vietnam
            foreach (var suggestion in suggestions)
            {
                if (suggestion.TryGetProperty("country_code", out var countryElement) && 
                    string.Equals(countryElement.GetString(), "vn", StringComparison.OrdinalIgnoreCase))
                {
                    return suggestion;
                }
            }
            
            // Fallback to the first suggestion
            return suggestions[0];
        }
        
        /// <summary>
        /// Gets the geographic coordinates for a Vietnamese city or district with improved accuracy
        /// </summary>
        public async Task<(double latitude, double longitude)> GetVietnameseLocationCoordinatesAsync(string cityOrDistrict)
        {
            if (string.IsNullOrWhiteSpace(cityOrDistrict))
            {
                _logger.LogWarning("Empty address provided to GetVietnameseLocationCoordinatesAsync");
                // Default coordinates for Da Nang
                return (16.047079, 108.206230);
            }
            
            // Check if this might be a detailed street address
            bool isDetailedAddress = IsLikelyStreetAddress(cityOrDistrict);
            
            _logger.LogInformation("Processing Vietnamese address: {Address}, Detected as detailed address: {IsDetailed}", 
                cityOrDistrict, isDetailedAddress);
            
            // For city-only searches, try direct matching first
            if (!isDetailedAddress && TryDirectCityMatch(cityOrDistrict, out var coordinates))
            {
                _logger.LogInformation("Direct city match found for: {Address}", cityOrDistrict);
                return coordinates;
            }
            
            try
            {
                // Format the bounding box string: west,south,east,north
                string bboxString = string.Join(",", _vietnamBBox);
                  // Select appropriate types parameter based on whether this is a detailed address or not
                string typesParam = isDetailedAddress 
                    ? "address,place,neighborhood,district,locality" // For detailed addresses, prioritize address and place types
                    : "place,district,locality,neighborhood";          // For general searches, prioritize administrative divisions
                
                // Build the URL with Vietnamese-specific parameters
                // For detailed addresses, use the Geocoding API as it's better for precise locations
                var geocodingUrl = $"https://api.mapbox.com/geocoding/v5/mapbox.places/{Uri.EscapeDataString(cityOrDistrict)}.json" +
                    $"?access_token={_mapboxAccessToken}" +
                    $"&country=vn" + // Limit results to Vietnam
                    $"&bbox={bboxString}" + // Use Vietnam bounding box
                    $"&language=vi" + // Prefer Vietnamese results
                    $"&limit=5" + // Get top 5 matches
                    $"&types={typesParam}" + // Types based on address detail level
                    $"&autocomplete=false"; // Complete search for exact address matching
                
                _logger.LogInformation("Using Geocoding API for Vietnamese location: {Url}", geocodingUrl);
                
                var response = await _httpClient.GetAsync(geocodingUrl);
                
                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Mapbox Geocoding API call failed with status: {Status}, Response: {Response}", 
                        response.StatusCode, errorContent);
                    
                    // When debugging is enabled, stop execution here
                    System.Diagnostics.Debugger.Break();
                    
                    // Fall back to the standard method
                    return await GetCoordinatesFromAddressAsync(cityOrDistrict);
                }
                
                var content = await response.Content.ReadAsStringAsync();
                var data = JsonDocument.Parse(content);
                
                var features = data.RootElement.GetProperty("features").EnumerateArray().ToList();
                
                if (features.Count == 0)
                {
                    _logger.LogWarning("No geocoding results found for Vietnamese location: {Location}", cityOrDistrict);
                    // Fall back to standard method
                    return await GetCoordinatesFromAddressAsync(cityOrDistrict);
                }
                
                // Find the best match for city or district
                var bestFeature = features[0]; // Default to first result
                
                // For city searches, prioritize features with type "place"
                foreach (var feature in features)
                {
                    var placeType = feature.GetProperty("place_type").EnumerateArray().FirstOrDefault();
                    string? placeTypeStr = placeType.ValueKind != JsonValueKind.Undefined ? placeType.GetString() : null;
                    
                    // Check if the place type is a city/place
                    if (placeTypeStr == "place")
                    {
                        // Check if the text matches our search closely
                        string? placeName = feature.GetProperty("text").GetString();
                        
                        if (!string.IsNullOrEmpty(placeName) && 
                            (string.Equals(placeName, cityOrDistrict, StringComparison.OrdinalIgnoreCase) ||
                             cityOrDistrict.Contains(placeName, StringComparison.OrdinalIgnoreCase) ||
                             placeName.Contains(cityOrDistrict, StringComparison.OrdinalIgnoreCase)))
                        {
                            bestFeature = feature;
                            break;
                        }
                    }
                }
                
                // Extract coordinates from the best match feature
                var center = bestFeature.GetProperty("center").EnumerateArray().ToArray();
                
                // Mapbox returns coordinates as [longitude, latitude]
                double lng = center.Length > 0 ? center[0].GetDouble() : 108.206230;
                double lat = center.Length > 1 ? center[1].GetDouble() : 16.047079;
                
                _logger.LogInformation("Successfully geocoded Vietnamese location: {Location} to coordinates: ({Lat}, {Lng})", 
                    cityOrDistrict, lat, lng);
                
                return (lat, lng);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error geocoding Vietnamese location: {Location}", cityOrDistrict);
                
                // When debugging is enabled, stop execution here
                System.Diagnostics.Debugger.Break();
                
                // Fall back to standard method
                return await GetCoordinatesFromAddressAsync(cityOrDistrict);
            }
        }
        
        /// <summary>
        /// Gets coordinates for a detailed Vietnamese street address using the Geocoding API instead of SearchBox
        /// </summary>
        private async Task<(double latitude, double longitude)> GetCoordinatesForDetailedAddressAsync(string detailedAddress)
        {
            try
            {
                // Format the bounding box string: west,south,east,north
                string bboxString = string.Join(",", _vietnamBBox);
                
                // For detailed addresses, use the Geocoding API as it's better for precise locations
                var geocodingUrl = $"https://api.mapbox.com/geocoding/v5/mapbox.places/{Uri.EscapeDataString(detailedAddress)}.json" +
                    $"?access_token={_mapboxAccessToken}" +
                    $"&country=vn" + // Limit results to Vietnam
                    $"&bbox={bboxString}" + // Use Vietnam bounding box                    $"&language=vi" + // Prefer Vietnamese results
                    $"&limit=5" + // Get top 5 matches
                    $"&types=address,place,neighborhood" + // Focus on addresses and places
                    $"&autocomplete=false"; // Complete search for exact address matching
                
                _logger.LogInformation("Using Geocoding API for detailed address: {Url}", geocodingUrl);
                
                var response = await _httpClient.GetAsync(geocodingUrl);
                
                if (!response.IsSuccessStatusCode)
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Mapbox Geocoding API call failed with status: {Status}, Response: {Response}", 
                        response.StatusCode, errorContent);
                    
                    // When debugging is enabled, stop execution here
                    System.Diagnostics.Debugger.Break();
                    
                    // Default coordinates for Da Nang
                    return (16.047079, 108.206230);
                }
                
                var content = await response.Content.ReadAsStringAsync();
                var data = JsonDocument.Parse(content);
                
                var features = data.RootElement.GetProperty("features").EnumerateArray().ToList();
                
                if (features.Count == 0)
                {
                    _logger.LogWarning("No geocoding results found for detailed address: {Address}", detailedAddress);
                    // Default coordinates for Da Nang
                    return (16.047079, 108.206230);
                }
                
                // Extract coordinates from the first (most relevant) feature
                var center = features[0].GetProperty("center").EnumerateArray().ToArray();
                
                // Mapbox returns coordinates as [longitude, latitude]
                double lng = center.Length > 0 ? center[0].GetDouble() : 108.206230;
                double lat = center.Length > 1 ? center[1].GetDouble() : 16.047079;
                
                _logger.LogInformation("Successfully geocoded detailed address: {Address} to coordinates: ({Lat}, {Lng})", 
                    detailedAddress, lat, lng);
                
                return (lat, lng);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error geocoding detailed address: {Address}", detailedAddress);
                
                // When debugging is enabled, stop execution here
                System.Diagnostics.Debugger.Break();
                
                // Default coordinates for Da Nang
                return (16.047079, 108.206230);
            }
        }
    }
}
