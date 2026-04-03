namespace ShoppingAPI.Models;

// Matches original VM records exactly
public record Order(int ProductId, int Qty);
public record Product(string Name, decimal Price, int Stock);
