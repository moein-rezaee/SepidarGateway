using System;
using System.Collections.Generic;
using System.Text;

namespace Sample.DTO
{
    class ItemResponse
    {
        public int ItemID { get; set; }
        public string Code { get; set; }
        public string Barcode { get; set; }
        public string Title { get; set; }
        public bool IsActive { get; set; }
        public bool IsSellable { get; set; }
        public int Type { get; set; }
        public int UnitRef { get; set; }
        public int? SecondaryUnitRef { get; set; }
        public double? UnitsRatio { get; set; }
        public decimal? Weight { get; set; }
        public decimal? Volume { get; set; }
        public IEnumerable<ItemTracingResponse> Tracings { get; set; }
        public IEnumerable<ItemTracingInventoryResponse> TracingInventories { get; set; }
        public decimal TotalInventory { get; set; }
        public IEnumerable<ItemPropertyValueResponse> PropertyValues { get; set; }
        public string Thumbnail { get; set; }
        public bool IsTaxExempt { get; set; }
        public decimal TaxRate { get; set; }
        public decimal DutyRate { get; set; }
        public bool BrokerSellable { get; set; }
        public int? SaleGroupRef { get; set; }
    }

    public class ItemPropertyValueResponse
    {
        public int PropertyRef { get; set; }
        public string Value { get; set; }
    }

    public class ItemTracingInventoryResponse
    {
        public int TracingRef { get; set; }
        public decimal Inventory { get; set; }
    }

    public class ItemTracingResponse
    {
        public int TracingID { get; set; }
        public bool IsSelectable { get; set; }
        public string Title { get; set; }
    }
}
