using System.Net;
using Dapper;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;
using ShoppingAPI.Models;

namespace ShoppingAPI.Functions;

public class ProductFunctions
{
    private readonly ILogger<ProductFunctions> _logger;
    private readonly string _conn;

    public ProductFunctions(ILogger<ProductFunctions> logger)
    {
        _logger = logger;
        _conn = Environment.GetEnvironmentVariable("SqlConnectionString")
                ?? throw new InvalidOperationException("SqlConnectionString app setting is missing.");
    }

    // GET /api/products
    [Function("GetProducts")]
    public async Task<HttpResponseData> GetProducts(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "products")] HttpRequestData req)
    {
        _logger.LogInformation("GET /api/products");
        try
        {
            using var db = new SqlConnection(_conn);
            var products = await db.QueryAsync("SELECT * FROM Products");
            var response = req.CreateResponse(HttpStatusCode.OK);
            response.Headers.Add("X-Served-By", Environment.GetEnvironmentVariable("WEBSITE_INSTANCE_ID") ?? "azure-functions");
            await response.WriteAsJsonAsync(products);
            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error fetching products");
            return req.CreateResponse(HttpStatusCode.InternalServerError);
        }
    }

    // POST /api/product
    [Function("AddProduct")]
    public async Task<HttpResponseData> AddProduct(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "product")] HttpRequestData req)
    {
        _logger.LogInformation("POST /api/product");
        try
        {
            var p = await req.ReadFromJsonAsync<Product>();
            if (p is null || string.IsNullOrWhiteSpace(p.Name))
            {
                var bad = req.CreateResponse(HttpStatusCode.BadRequest);
                await bad.WriteStringAsync("Invalid product body.");
                return bad;
            }

            using var db = new SqlConnection(_conn);
            await db.ExecuteAsync(
                "INSERT INTO Products(Name,Price,Stock) VALUES(@Name,@Price,@Stock)", p);

            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteStringAsync("Product added");
            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error adding product");
            return req.CreateResponse(HttpStatusCode.InternalServerError);
        }
    }

    // POST /api/order
    [Function("PlaceOrder")]
    public async Task<HttpResponseData> PlaceOrder(
        [HttpTrigger(AuthorizationLevel.Anonymous, "post", Route = "order")] HttpRequestData req)
    {
        _logger.LogInformation("POST /api/order");
        try
        {
            var o = await req.ReadFromJsonAsync<Order>();
            if (o is null)
            {
                var bad = req.CreateResponse(HttpStatusCode.BadRequest);
                await bad.WriteStringAsync("Invalid order body.");
                return bad;
            }

            using var db = new SqlConnection(_conn);

            var stock = await db.ExecuteScalarAsync<int>(
                "SELECT Stock FROM Products WHERE Id=@id",
                new { id = o.ProductId });

            if (stock < o.Qty)
            {
                var bad = req.CreateResponse(HttpStatusCode.BadRequest);
                await bad.WriteStringAsync("Out of stock");
                return bad;
            }

            await db.ExecuteAsync(
                "UPDATE Products SET Stock = Stock - @qty WHERE Id=@id",
                new { qty = o.Qty, id = o.ProductId });

            await db.ExecuteAsync(
                "INSERT INTO Orders(ProductId,Qty) VALUES(@id,@qty)",
                new { id = o.ProductId, qty = o.Qty });

            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteStringAsync("Order placed");
            return response;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error placing order");
            return req.CreateResponse(HttpStatusCode.InternalServerError);
        }
    }
}