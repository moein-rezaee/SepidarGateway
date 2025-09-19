namespace Sample.DTO
{
    class LoginResponse
    {
        public string Token { get; set; }
        public int UserID { get; set; }
        public string Title { get; set; }
        public bool CanEditCustomer { get; set; }
        public bool CanRegisterCustomer { get; set; }
        public bool CanRegisterOrder { get; set; }
        public bool CanRegisterReturnOrder { get; set; }
        public bool CanRegisterInvoice { get; set; }
        public bool CanRegisterReturnInvoice { get; set; }
        public bool CanPrintInvoice { get; set; }
        public bool CanPrintReturnInvoice { get; set; }
        public bool CanPrintInvoiceBeforeSend { get; set; }
        public bool CanPrintReturnInvoiceBeforeSend { get; set; }
        public bool CanRevokeInvoice { get; set; }
    }
}
