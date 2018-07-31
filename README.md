# LoginNetCore
Proyecto con referencias a Identity y JWT.

Éste proyecto esta pensado como prueba de concepto, sirve las herramientas necesarias para hacer login, generar en el __header__ el token resultante y mantenerlo vivo en cada llamada devolviendo en el response el token recibido en el request.

## Uso del ensamblado
El ensamblado implementa tre extensiones de configuración de los cuales, dos de ellos `AddIdentity` y `AddJWT` son extensiones de servicio encargados de la configuración de __Identity__ y __JWT__ respectivamente:
```
public void ConfigureServices(IServiceCollection services)
{
    services.AddScoped<JWTProvider>();

    services.AddDbContext<CustomDbContext>(options => options.UseMySql(connectionString, mysqlOptions =>
            {
                mysqlOptions.ServerVersion(new Version(5, 7, 22), ServerType.MySql); // replace with your Server Version and Type
            }));
    services.AddIdentity<CustomDbContext>();
    services.AddJWT();

    services.AddMvc();
}
```
>Se ha de registrar en el contenedor de inyeccion como __Scope__ el provider `JWTProvider` para que se comparta la misma instancia generada allá donde se necesite.

El tercer metodo de extensión, `UseJwtHeader`, es sobre `IApplicationBuilder` y configura el middleware encargado de registrar en el __Header__ el token.
```
public void Configure(IApplicationBuilder app, IHostingEnvironment env)
{
if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
            }

            app.UseJwtHeader();
            app.UseHttpsRedirection();
            app.UseAuthentication();

            app.UseMvc();
}
```

## Controller
El `Controller` encargado de autenticar las credenciales será el responsable de generar el token:

```
[HttpPost]
[Route("login")]
public async Task<IActionResult> Login([FromBody]RegistrationModel model, [FromServices]JWTProvider jwt)
{
    if (!ModelState.IsValid)
    {
        return BadRequest(ModelState);
    }

    var user = await _signInManager.UserManager.FindByEmailAsync(model.Email);
    var check = await _signInManager.UserManager.CheckPasswordAsync(user, model.Password);

    if (check)
    {
        jwt.GenerateToken(user);
        return new OkObjectResult("Se ha autenticado con éxito.");
    }

    return new BadRequestObjectResult("El correo o la contraseña no es correcta.");
}
```

## La validación del token en el Request
La validación del token enviado por el cliente en el __Request__ se realiza en `JWTProvider::ValidateTokenHandle`. Éste método se ejecuta cada vez que se ha de validar el token del Request, es decir, cada vez que entra una petición del cliente. Descifra el token y utiliza la información de los __Claims__ para hacer una llamada a base de datos solicitando el Id de usuario y validando los campos __userName__ y __hashPassword__.

## Notas
>El encargado de mantener el token vivo entre las llamadas es el método `JWTHeaderMiddleware.CreateToken` del middleware. Aquí se tendria que __validar el periodo de expiración__ del token y hactuar en consecuencia.