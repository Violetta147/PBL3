namespace PBL3.ViewModel.Menu
{
    // ViewModel cho một Menu
    public class MenuViewModel
    {
        public int Id { get; set; }
        public string Title { get; set; }
        public string? Description { get; set; }
        public List<MenuSectionViewModel> MenuSections { get; set; }
        public bool IsActive { get; set; }
        public int DisplayOrder { get; set; }
        public MenuViewModel() { MenuSections = new List<MenuSectionViewModel>(); }
    }
}
