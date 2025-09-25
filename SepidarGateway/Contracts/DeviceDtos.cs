using System;

namespace SepidarGateway.Contracts;

public sealed class DeviceRegisterRequestDto
{
    public string DeviceSerial { get; set; } = string.Empty;
}

public sealed class DeviceLoginRequestDto
{
    public string? UserName { get; set; }

    public string? Password { get; set; }

    public string? IntegrationId { get; set; }

    public string? GenerationVersion { get; set; }

    public string? DeviceSerial { get; set; }

    public DeviceRegisterPayloadDto? RegisterPayload { get; set; }
}

public sealed class DeviceRegisterPayloadDto
{
    public string? Cypher { get; set; }

    public string? Iv { get; set; }

    public string? DeviceTitle { get; set; }
}

public sealed class DeviceLoginResponseDto
{
    public string Token { get; set; } = string.Empty;
    public int ExpiresIn { get; set; }
    public DateTimeOffset ExpiresAt { get; set; }
    public int UserId { get; set; }
    public string? UserName { get; set; }
    public string? Title { get; set; }
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
