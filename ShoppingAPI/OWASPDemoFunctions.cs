using System.Diagnostics;
using System.Net;
using Dapper;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;

namespace ShoppingAPI.Functions;

/// <summary>
/// WARNING: Intentionally vulnerable endpoints — for WAF training / demo only.
/// Do NOT enable in production without an Azure WAF (Application Gateway or Front Door) in front.
/// Mirrors the original /demo/* endpoints from the App VM Program.cs exactly.
/// </summary>
public class OWASPDemoFunctions
{
    private readonly ILogger<OWASPDemoFunctions> _logger;
    private readonly string _conn;

    public OWASPDemoFunctions(ILogger<OWASPDemoFunctions> logger)
    {
        _logger = logger;
        _conn = Environment.GetEnvironmentVariable("SqlConnectionString")
                ?? throw new InvalidOperationException("SqlConnectionString app setting is missing.");
    }

    // ── GET /api/demo/sqli?q= ─────────────────────────────────────────────────
    // VULNERABLE: SQL Injection — raw string concatenation, intentional
    // Original: app.MapGet("/demo/sqli", async (string? q) => { ... })
    [Function("Demo_SQLi")]
    public async Task<HttpResponseData> SqlInjection(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "demo/sqli")] HttpRequestData req)
    {
        var q = System.Web.HttpUtility.ParseQueryString(req.Url.Query)["q"];

        if (string.IsNullOrEmpty(q))
        {
            var bad = req.CreateResponse(HttpStatusCode.BadRequest);
            await bad.WriteStringAsync("Provide ?q= parameter");
            return bad;
        }

        // INTENTIONALLY VULNERABLE — do not parameterise
        var sql = "SELECT * FROM Products WHERE Name = '" + q + "'";

        try
        {
            using var db = new SqlConnection(_conn);
            var result = (await db.QueryAsync(sql)).ToList();

            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteAsJsonAsync(new
            {
                query_executed = sql,
                rows_returned  = result.Count,
                data           = result
            });
            return response;
        }
        catch (Exception ex)
        {
            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteAsJsonAsync(new
            {
                query_executed = sql,
                sql_error      = ex.Message,
                hint           = "SQL error — injection was partially successful"
            });
            return response;
        }
    }

    // ── GET /api/demo/xss?q= ──────────────────────────────────────────────────
    // VULNERABLE: Reflected XSS — raw input echoed into HTML
    // Original: app.MapGet("/demo/xss", (string? q) => { ... })
    [Function("Demo_XSS")]
    public async Task<HttpResponseData> ReflectedXss(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "demo/xss")] HttpRequestData req)
    {
        var q = System.Web.HttpUtility.ParseQueryString(req.Url.Query)["q"];

        if (string.IsNullOrEmpty(q))
        {
            var bad = req.CreateResponse(HttpStatusCode.BadRequest);
            await bad.WriteStringAsync("Provide ?q= parameter");
            return bad;
        }

        // INTENTIONALLY VULNERABLE — no encoding applied
        var html = "<!DOCTYPE html><html><body>" +
                   "<h2>Search Results for: " + q + "</h2>" +
                   "<p>Input reflected without encoding. Script executes if WAF is disabled.</p>" +
                   "</body></html>";

        var response = req.CreateResponse(HttpStatusCode.OK);
        response.Headers.Add("Content-Type", "text/html");
        await response.WriteStringAsync(html);
        return response;
    }

    // ── GET /api/demo/lfi?file= ───────────────────────────────────────────────
    // VULNERABLE: Path Traversal / Local File Inclusion
    // Original: app.MapGet("/demo/lfi", async (string? file) => { ... })
    [Function("Demo_LFI")]
    public async Task<HttpResponseData> LocalFileInclusion(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "demo/lfi")] HttpRequestData req)
    {
        var file = System.Web.HttpUtility.ParseQueryString(req.Url.Query)["file"];

        if (string.IsNullOrEmpty(file))
        {
            var bad = req.CreateResponse(HttpStatusCode.BadRequest);
            await bad.WriteStringAsync("Provide ?file= parameter");
            return bad;
        }

        try
        {
            // Normalize path separators (matches original Windows VM behaviour)
            var normalizedPath = file.Replace("/", "\\");
            var content = await File.ReadAllTextAsync(normalizedPath);

            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteAsJsonAsync(new
            {
                file_requested = file,
                size_bytes     = content.Length,
                content        = content,
                warning        = "FILE READ SUCCESSFULLY — WAF should have blocked this request"
            });
            return response;
        }
        catch (UnauthorizedAccessException)
        {
            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteAsJsonAsync(new
            {
                file_requested = file,
                error          = "Access denied by OS — but WAF should block BEFORE reaching the server",
                hint           = "Even access denied proves the request reached the backend"
            });
            return response;
        }
        catch (Exception ex)
        {
            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteAsJsonAsync(new
            {
                file_requested = file,
                error          = ex.Message,
                hint           = "Request reached backend — WAF did not block the path traversal"
            });
            return response;
        }
    }

    // ── GET /api/demo/cmdi?cmd= ───────────────────────────────────────────────
    // VULNERABLE: Command Injection — executes arbitrary OS commands via PowerShell
    // Original: app.MapGet("/demo/cmdi", async (string? cmd) => { ... })
    [Function("Demo_CMDi")]
    public async Task<HttpResponseData> CommandInjection(
        [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "demo/cmdi")] HttpRequestData req)
    {
        var cmd = System.Web.HttpUtility.ParseQueryString(req.Url.Query)["cmd"];

        if (string.IsNullOrEmpty(cmd))
        {
            var bad = req.CreateResponse(HttpStatusCode.BadRequest);
            await bad.WriteStringAsync("Provide ?cmd= parameter");
            return bad;
        }

        try
        {
            // Azure Functions runs on Linux by default — use /bin/sh instead of powershell.exe
            // If your Function App is Windows plan, swap back to powershell.exe
            var isWindows = OperatingSystem.IsWindows();

            var psi = isWindows
                ? new ProcessStartInfo("powershell.exe")
                  {
                      Arguments              = $"-NonInteractive -NoProfile -Command \"{cmd}\"",
                      RedirectStandardOutput = true,
                      RedirectStandardError  = true,
                      UseShellExecute        = false,
                      CreateNoWindow         = true
                  }
                : new ProcessStartInfo("/bin/sh")
                  {
                      Arguments              = $"-c \"{cmd}\"",
                      RedirectStandardOutput = true,
                      RedirectStandardError  = true,
                      UseShellExecute        = false,
                      CreateNoWindow         = true
                  };

            using var process = Process.Start(psi)!;
            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask  = process.StandardError.ReadToEndAsync();
            var completed  = process.WaitForExit(10000); // 10s timeout — same as original

            var output = await outputTask;
            var error  = await errorTask;

            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteAsJsonAsync(new
            {
                command_executed = cmd,
                exit_code        = completed ? process.ExitCode : -1,
                output           = string.IsNullOrEmpty(output) ? "(no output)" : output.Trim(),
                error            = string.IsNullOrEmpty(error)  ? "(no error)"  : error.Trim(),
                warning          = "COMMAND EXECUTED ON SERVER — WAF should have blocked this"
            });
            return response;
        }
        catch (Exception ex)
        {
            var response = req.CreateResponse(HttpStatusCode.OK);
            await response.WriteAsJsonAsync(new
            {
                command_executed = cmd,
                error            = ex.Message,
                hint             = "Request reached backend but command failed"
            });
            return response;
        }
    }
}
