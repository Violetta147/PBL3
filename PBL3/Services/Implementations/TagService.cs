using Microsoft.EntityFrameworkCore;
using PBL3.Data;
using PBL3.Models;
using PBL3.Services.Interfaces; // Using cho interface
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace PBL3.Services.Implementations
{
    public class TagService : ITagService
    {
        private readonly ApplicationDbContext _context;

        public TagService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<Tag>> GetAllAsync()
        {
            // Sắp xếp theo tên để hiển thị danh sách có thứ tự
            return await _context.Tags.OrderBy(t => t.Name).ToListAsync();
        }

        public async Task<Tag?> GetByIdAsync(int id)
        {
            return await _context.Tags.FindAsync(id);
        }

        // (Tùy chọn - Triển khai các phương thức CRUD cho Admin nếu cần sau này)
        // ... (Tương tự như CuisineTypeService)
    }
}
