using System.Collections.Generic;
using X.PagedList;

namespace PBL3.ViewModel
{
    public class SearchViewModel
    {   
        // Search parameters
        public string SearchTerm { get; set; } = string.Empty;
        public string Address { get; set; } = "Liên Chiểu, Đà Nẵng";

        //default da nang
        public double? Lat { get; set; } = 16.075000;
        public double? Lng { get; set; } = 108.206230;

        public IEnumerable<int>? TagIds { get; set; } = new List<int>();
        public IEnumerable<int>? CuisineTypeIds { get; set; } = new List<int>();

        public string? SortBy { get; set; } = "relevance";
        public decimal? MinPrice { get; set; }
        public decimal? MaxPrice { get; set; }
        public string? MaxDistance { get; set; } = string.Empty;

        public IPagedList<RestaurantCardViewModel>? RestaurantCards { get; set; }

        public int Page { get; set; } = 1;
        public int PageSize { get; set; } = 10;
    }
}