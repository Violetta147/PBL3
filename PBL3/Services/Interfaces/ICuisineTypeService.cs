using PBL3.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace PBL3.Services.Interfaces
{
    public interface ICuisineTypeService
    {
        /// <summary>
        /// Lấy tất cả các loại hình ẩm thực.
        /// </summary>
        Task<IEnumerable<CuisineType>> GetAllAsync();

        /// <summary>
        /// Lấy một loại hình ẩm thực theo ID.
        /// </summary>
        Task<CuisineType?> GetByIdAsync(int id);

        // (Tùy chọn - Cho Admin)
        // Task CreateAsync(CuisineType cuisineType);
        // Task UpdateAsync(CuisineType cuisineType);
        // Task DeleteAsync(int id);
    }
}
