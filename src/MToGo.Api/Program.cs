using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.Text.Json.Serialization;

var builder = WebApplication.CreateBuilder(args);

// Strict JSON (reject unknown fields)
builder.Services.ConfigureHttpJsonOptions(opt =>
{
    opt.SerializerOptions.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow;
});

// AuthN/Z (JWT) - relaxed for local/demo; tighten in prod by setting Jwt:Authority/Audience
var authority = builder.Configuration["Jwt:Authority"];
var audience  = builder.Configuration["Jwt:Audience"];

builder.Services.AddAuthentication("Bearer")
    .AddJwtBearer("Bearer", o =>
    {
        if (!string.IsNullOrWhiteSpace(authority))
        {
            o.Authority = authority;
            o.RequireHttpsMetadata = true;
        }
        if (!string.IsNullOrWhiteSpace(audience))
        {
            o.Audience = audience;
        }
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = !string.IsNullOrWhiteSpace(authority),
            ValidateAudience = !string.IsNullOrWhiteSpace(audience),
            ValidateIssuerSigningKey = false,
            ValidateLifetime = false,
            RequireExpirationTime = false,
            RequireSignedTokens = false
        };
    });

builder.Services.AddAuthorization(opts =>
{
    opts.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();

    opts.AddPolicy("IsOwner", policy => policy.RequireAssertion(ctx =>
    {
        var http = ctx.Resource as HttpContext;
        var routeId = http?.Request.RouteValues["userId"]?.ToString();
        var sub = ctx.User.FindFirst("sub")?.Value;
        return !string.IsNullOrEmpty(routeId) && routeId == sub;
    }));
});

// Global rate limiting (per user/IP)
builder.Services.AddRateLimiter(_ => _.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(
    http => RateLimitPartition.GetFixedWindowLimiter(
        partitionKey: http.User.Identity?.IsAuthenticated == true
            ? http.User.FindFirst("sub")?.Value ?? http.Connection.RemoteIpAddress?.ToString() ?? "anon"
            : http.Connection.RemoteIpAddress?.ToString() ?? "anon",
        factory: _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = 100,
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0,
        })));

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Security headers
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    ctx.Response.Headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()";
    await next();
});

// Only force HTTPS/HSTS outside Development
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
    app.UseHttpsRedirection();
}

app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

// Health endpoints
app.MapGet("/health/ready", () => Results.Ok("ready")).AllowAnonymous();
app.MapGet("/health/live",  () => Results.Ok("live")).AllowAnonymous();

// Example protected endpoint with ownership check
app.MapGet("/api/users/{userId}/orders", ([FromRoute] string userId) => Results.Ok(new { userId }))
   .RequireAuthorization("IsOwner");

// Strict JSON example: unknown fields -> 400

app.MapPost("/api/some-endpoint", ([FromBody] KnownRequest req) => Results.Ok(new { req.known }));

app.Run();

public record KnownRequest(string known)
{
    public int UnknownField { get; set; }
}

public partial class Program { }
