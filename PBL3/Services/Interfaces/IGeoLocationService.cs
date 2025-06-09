using System;
using System.Threading.Tasks;

namespace PBL3.Services.Interfaces
{
    public interface IGeoLocationService
    {
        /// <summary>
        /// Gets the geographic coordinates (latitude and longitude) for a given address using Mapbox API
        /// </summary>
        /// <param name="address">The address to geocode</param>
        /// <returns>A tuple containing the latitude and longitude coordinates</returns>
        Task<(double latitude, double longitude)> GetCoordinatesFromAddressAsync(string address);
        
        /// <summary>
        /// Gets the geographic coordinates for a Vietnamese city or district with improved accuracy
        /// </summary>
        /// <param name="cityOrDistrict">The Vietnamese city or district name (e.g., "Hà Nội", "Quận 1")</param>
        /// <returns>A tuple containing the latitude and longitude coordinates</returns>
        Task<(double latitude, double longitude)> GetVietnameseLocationCoordinatesAsync(string cityOrDistrict);
    }
}