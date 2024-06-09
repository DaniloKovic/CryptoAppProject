using CryptoAppProject.Repository.RepositoryClasses;
using CryptoAppProject.Repository.RepositoryInterfaces;
using CryptoAppProject.Services.Interface;
using CryptoAppProject.Services.Implementation;
using CryptoAppProject.Middleware;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using CryptoAppProject.Implementation;
using CryptoAppProject.Services;

namespace CryptoAppProject.ExtensionHelper
{
    public static class ConfigExtension
    {
        public static void ConfigureServicesExtension(this IServiceCollection services)
        {
            services.AddScoped<IUserRepository, UserRepository>();
            services.AddScoped<ILogActivityRepository, LogActivityRepository>();
            services.AddScoped<IRailFenceService, RailFenceService>();
            services.AddScoped<IMyszkowskiService, MyszkowskiService>();
            services.AddScoped<IPlayfairService, PlayfairService>();
            services.AddScoped<ICryptoService, CryptoService>();
        }

        public static void ConfigureMiddleware(this IServiceCollection services)
        {
            services.AddTransient<ExceptionHandlingMiddleware>();
        }

        public static void ConfigureAuthenticationExtension(this IServiceCollection services, IConfiguration config)
        {
            services.AddAuthentication(optiones =>
            {
                optiones.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                optiones.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                optiones.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(o =>
            {
                o.UseSecurityTokenValidators = true;
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidAudience = config["JwtSecurityToken:Audience"],
                    ValidIssuer = config["JwtSecurityToken:Issuer"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["JwtSecurityToken:Key"])),
                    ValidateIssuer = true,
                    ValidateAudience = false,
                    ValidateIssuerSigningKey = true,
                    ValidateLifetime = false,
                    ClockSkew = TimeSpan.Zero,
                };
            });
        }
    }
}
