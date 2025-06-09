using PBL3.Models;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace PBL3.Services.Interfaces
{
    public interface ITagService
    {
        /// <summary>
        /// Lấy tất cả các thẻ.
        /// </summary>
        Task<IEnumerable<Tag>> GetAllAsync();

        /// <summary>
        /// Lấy một thẻ theo ID.
        /// </summary>
        Task<Tag?> GetByIdAsync(int id);

        // (Tùy chọn - Cho Admin)
        // Task CreateAsync(Tag tag);
        // Task UpdateAsync(Tag tag);
        // Task DeleteAsync(int id);
    }
}
