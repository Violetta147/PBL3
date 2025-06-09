namespace PBL3.ViewModel.Menu
{
    // ViewModel cho một MenuItem rút gọn để hiển thị trong menu
    public class MenuItemSummaryViewModel
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string? Description { get; set; }
        public string PriceDisplay { get; set; } // Ví dụ: "50.000 VNĐ"
        public string? MainImageUrl { get; set; } // Ảnh đại diện của món ăn
        public List<string> CategoryNames { get; set; }
        public bool IsAvailable { get; set; }
        public bool IsSignatureDish { get; set; }
        public int DisplayOrder { get; set; }
        public MenuItemSummaryViewModel()
        {
            CategoryNames = new List<string>();
        }
    }
}
