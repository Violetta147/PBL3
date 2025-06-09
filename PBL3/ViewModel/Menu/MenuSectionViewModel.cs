namespace PBL3.ViewModel.Menu
{
    // ViewModel cho một MenuSection
    public class MenuSectionViewModel
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string? Description { get; set; }
        public List<MenuItemSummaryViewModel> MenuItems { get; set; }
        public int DisplayOrder { get; set; }
        public MenuSectionViewModel() { MenuItems = new List<MenuItemSummaryViewModel>(); }
    }
}
