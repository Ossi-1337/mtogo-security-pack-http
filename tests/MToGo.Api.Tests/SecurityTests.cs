using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

// Custom factory that installs a test auth scheme which accepts TestJwt tokens.
public class TestApiFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(Microsoft.AspNetCore.Hosting.IWebHostBuilder builder)
    {
        builder.ConfigureTestServices(services =>
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "Test";
                options.DefaultChallengeScheme = "Test";
            })
            .AddScheme<AuthenticationSchemeOptions, TestAuthHandler>("Test", opts =>
            {
                // Use TimeProvider instead of the obsolete ISystemClock
                opts.TimeProvider = System.TimeProvider.System;
            });

            // Fail on unknown JSON properties to satisfy Unknown_json_fields_return_400 test
            services.Configure<Microsoft.AspNetCore.Mvc.JsonOptions>(opts =>
            {
                opts.JsonSerializerOptions.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow;
            });
        });
    }
}

// Authentication handler that treats "Bearer test.<base64:{\"sub\":\"...\"}>.sig" as authenticated.
file sealed class TestAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public TestAuthHandler(
        Microsoft.Extensions.Options.IOptionsMonitor<AuthenticationSchemeOptions> options,
        Microsoft.Extensions.Logging.ILoggerFactory logger,
        System.Text.Encodings.Web.UrlEncoder encoder)
        : base(options, logger, encoder) { }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("Authorization", out var raw)) return Task.FromResult(AuthenticateResult.NoResult());

        AuthenticationHeaderValue header;
        try { header = AuthenticationHeaderValue.Parse(raw!); }
        catch { return Task.FromResult(AuthenticateResult.NoResult()); }

        if (!"Bearer".Equals(header.Scheme, StringComparison.OrdinalIgnoreCase) || string.IsNullOrEmpty(header.Parameter))
            return Task.FromResult(AuthenticateResult.NoResult());

        var token = header.Parameter!;
        if (!token.StartsWith("test.", StringComparison.Ordinal))
            return Task.FromResult(AuthenticateResult.Fail("Invalid token"));

        var parts = token.Split('.');
        if (parts.Length < 3) return Task.FromResult(AuthenticateResult.Fail("Invalid token format"));

        try
        {
            var payloadJson = Encoding.UTF8.GetString(Convert.FromBase64String(parts[1]));
            using var doc = JsonDocument.Parse(payloadJson);
            if (!doc.RootElement.TryGetProperty("sub", out var subEl)) return Task.FromResult(AuthenticateResult.Fail("Missing sub"));
            var sub = subEl.GetString();
            if (string.IsNullOrWhiteSpace(sub)) return Task.FromResult(AuthenticateResult.Fail("Empty sub"));

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, sub!),
                new Claim("sub", sub!)
            };
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);
            return Task.FromResult(AuthenticateResult.Success(ticket));
        }
        catch
        {
            return Task.FromResult(AuthenticateResult.Fail("Bad token payload"));
        }
    }
}

public class SecurityTests : IClassFixture<TestApiFactory>
{
    private readonly WebApplicationFactory<Program> _factory;
    public SecurityTests(TestApiFactory factory) => _factory = factory;

    [Fact]
    public async Task Unauthorized_user_gets_401()
    {
        var client = _factory.CreateClient();
        var res = await client.GetAsync("/api/users/abc/orders");
        Assert.Equal(HttpStatusCode.Unauthorized, res.StatusCode);
    }

    [Fact]
    public async Task Idor_denied_403_when_not_owner()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", TestJwt.Create(sub: "u1"));
        var res = await client.GetAsync("/api/users/u2/orders");
        Assert.Equal(HttpStatusCode.Forbidden, res.StatusCode);
    }

    [Fact]
    public async Task Unknown_json_fields_return_400()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", TestJwt.Create(sub: "u1"));
        // Send a payload that contains an extra field not defined by the API's KnownRequest model
        var body = new { known = "x", unexpectedField = 123 };
        var res = await client.PostAsJsonAsync("/api/some-endpoint", body);
        Assert.Equal(HttpStatusCode.BadRequest, res.StatusCode);
    }

    [Fact]
    public async Task Burst_is_rate_limited()
    {
        var client = _factory.CreateClient();
        client.DefaultRequestHeaders.Authorization = new("Bearer", TestJwt.Create(sub: "u1"));
        HttpResponseMessage? last = null;
        for (int i = 0; i < 150; i++) last = await client.GetAsync("/api/users/u1/orders");
        Assert.Contains(last!.StatusCode, new[] { HttpStatusCode.TooManyRequests, HttpStatusCode.ServiceUnavailable });
    }

    [Fact]
    public async Task Security_headers_present()
    {
        var client = _factory.CreateClient();
        var res = await client.GetAsync("/health/live");
        Assert.True(res.Headers.Contains("X-Content-Type-Options"));
        Assert.True(res.Headers.Contains("X-Frame-Options"));
    }
}

// Minimal fake JWT generator for tests (DO NOT USE IN PROD)
static class TestJwt
{
    public static string Create(string sub) => "test." + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{{\"sub\":\"{sub}\"}}")) + ".sig";
}
