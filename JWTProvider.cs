using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;

namespace Security
{
    /// <summary>
    /// Usado para asociar el usuario autenticado y generar un token en el header.
    /// </summary>
    public class JWTProvider
    {
        /// <summary>
        /// Delegado que se ejecuta cuando se genera un token con el método <see cref="GenerateToken"/>.
        /// </summary>
        internal Action<string> Invoke { get; set; }

        /// <summary>
        /// Genera un token e inyecta en el Header el token de autenticación siempre que se haya configurado el middleware en el <see cref="Startup"/>.
        /// <example>
        ///     app.UseJwtHeader();
        /// </example>
        /// </summary>
        /// <param name="user"></param>
        public string GenerateToken(IdentityUser user)
        {
            if (user == null) throw new ArgumentNullException($"Para generar un Token el parametro {nameof(user)} no puede ser nulo.");

            var result = BuildToken(user);
            Invoke?.Invoke(result);

            return result;
        }

        public string BuildToken(IdentityUser user)
        {
            if (user == null) return string.Empty;

            // creamos una lista de todos los valores que queremos serializar en el token.
            var claimsIdentity = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Hash, user.PasswordHash),
                new Claim(ClaimTypes.Role, "Administrators")
            };

            // Preparamos los valores de configuración del token
            var secretKey = "68906561-B44A-4083-9DBC-A57FAC481DDF";
            string audienceToken = "localhost:53672";
            string issuerToken = "localhost:53672";
            var expireTime = DateTime.Now.AddMinutes(30);

            var securityKey = new SymmetricSecurityKey(Encoding.Default.GetBytes(secretKey));
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            // Creamos y ciframos el token
            Func<SecurityToken, string> tokenHandler = new JwtSecurityTokenHandler().WriteToken;
            var jwtSecurityToken = new JwtSecurityToken(
                audience: audienceToken,
                issuer: issuerToken,
                claims: claimsIdentity,
                notBefore: DateTime.UtcNow,
                expires: expireTime,
                signingCredentials: signingCredentials);

            var jwtTokenString = tokenHandler(jwtSecurityToken);
            return jwtTokenString;
        }

        /// <summary>
        /// Valida en cada request el token contra la base de datos.
        /// </summary>
        /// <param name="securityKey"></param>
        /// <param name="securityToken"></param>
        /// <param name="tokenValidationParameters"></param>
        /// <param name="signInManager"></param>
        /// <returns></returns>
        internal static bool ValidateTokenHandle(SecurityKey securityKey, SecurityToken securityToken, TokenValidationParameters tokenValidationParameters, SignInManager<IdentityUser> signInManager)
        {
            //Ejemplo de como se validaría el token contra la base de datos.
            //Ésto habría que hacerlo asíncrono y eligiendo los campos a validar además del nombre.
            if (!(securityToken is JwtSecurityToken token)) return false;

            var idUser = token.Claims.Single(x => x.Type == ClaimTypes.NameIdentifier).Value;
            var nameUser = token.Claims.Single(x => x.Type == ClaimTypes.Name).Value;
            var hashPassword = token.Claims.Single(x => x.Type == ClaimTypes.Hash).Value;

            var user = signInManager.UserManager.FindByIdAsync(idUser).Result;
            return user?.UserName == nameUser && user?.PasswordHash == hashPassword;
        }

    }
}
