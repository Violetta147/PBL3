using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace PBL3.ViewModel
{
    public class DirectionsViewModel
    {
        public double Latitude { get; set; }
        public double Longitude { get; set; }
        public int? LocationId { get; set; }
        public string LocationName { get; set; }
        public string LocationAddress { get; set; }
    }
}