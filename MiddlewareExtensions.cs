namespace Microsoft.AspNetCore.Builder
{
    using Security;

    public static class MiddlewareExtensions
    {
        public static IApplicationBuilder UseJwtHeader(this IApplicationBuilder app)
        {
            app.UseMiddleware<JWTHeaderMiddleware>();
            return app;
        }
    }
}
