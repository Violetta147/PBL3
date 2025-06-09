using Microsoft.EntityFrameworkCore;
using PBL3.Data;
using PBL3.Models;
using PBL3.Services.Interfaces; // Using cho interface
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace PBL3.Services.Implementations
{
    public class CuisineTypeService : ICuisineTypeService
    {
        private readonly ApplicationDbContext _context;

        public CuisineTypeService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<IEnumerable<CuisineType>> GetAllAsync()
        {
            // Sắp xếp theo tên để hiển thị danh sách có thứ tự
            return await _context.CuisineTypes.OrderBy(ct => ct.Name).ToListAsync();
        }

        public async Task<CuisineType?> GetByIdAsync(int id)
        {
            return await _context.CuisineTypes.FindAsync(id);
        }

        // (Tùy chọn - Triển khai các phương thức CRUD cho Admin nếu cần sau này)
        // public async Task CreateAsync(CuisineType cuisineType)
        // {
        //     _context.CuisineTypes.Add(cuisineType);
        //     await _context.SaveChangesAsync();
        // }

        // public async Task UpdateAsync(CuisineType cuisineType)
        // {
        //     _context.Entry(cuisineType).State = EntityState.Modified;
        //     await _context.SaveChangesAsync();
        // }

        // public async Task DeleteAsync(int id)
        // {
        //     var cuisineType = await _context.CuisineTypes.FindAsync(id);
        //     if (cuisineType != null)
        //     {
        //         _context.CuisineTypes.Remove(cuisineType);
        //         await _context.SaveChangesAsync();
        //     }
        // }
    }
}
