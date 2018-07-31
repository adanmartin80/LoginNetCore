using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Security
{
    public class JWTHeaderMiddleware
    {
        private RequestDelegate _next;

        public JWTHeaderMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        //public async Task Invoke(HttpContext context)
        //{
        //    var watch = new System.Diagnostics.Stopwatch();
        //    watch.Start();

        //    //To add Headers AFTER everything you need to do this
        //    context.Response.OnStarting(state => {
        //        var httpContext = (HttpContext)state;
        //        httpContext.Response.Headers.Add("X-Response-Time-Milliseconds", new[] { watch.ElapsedMilliseconds.ToString() });
        //        return Task.FromResult(0);
        //    }, context);

        //    await _next(context);
        //}
        public async Task Invoke(HttpContext httpContext, JWTProvider jwt)
        {
            //Entrada por el pipline del request.
            //Hacer algo...

            CreateToken(httpContext, jwt);
            await _next(httpContext);

            //Salida por el pipline del request.
        }

        private void CreateToken(HttpContext httpContext, JWTProvider jwt)
        {
            //Si viene un Token del cliente, añadimos ése token en la respuesta (TODO: modificar ésto para contemplar caducidad del token).
            if (httpContext.Request.Headers.ContainsKey("Authorization"))
                httpContext.Response.OnStarting(state => {
                    var context = (HttpContext)state;
                    context.Response.Headers.Add("Authorization", $"{httpContext.Request.Headers["Authorization"]}");
                    return Task.CompletedTask;
                }, httpContext);

            //Si en la respuesta no hay un token, intentamos generar uno y añadirlo en la cabecera.
            else if (!httpContext.Response.Headers.ContainsKey("Authorization"))
                jwt.Invoke = token => {
                    httpContext.Response.OnStarting(state => {
                        var context = (HttpContext)state;
                        context.Response.Headers.Add("Authorization", $"Bearer {token}");
                        return Task.CompletedTask;
                    }, httpContext);
                };
             
        }
    }
}
