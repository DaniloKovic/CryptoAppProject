using CryptoAppProject;
using System;
using CryptoAppProject.Exception;
using CryptoAppProject.Repository;
using CryptoAppProject.Repository.RepositoryClasses;
using CryptoAppProject.Repository.RepositoryInterfaces;
using Microsoft.EntityFrameworkCore;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers(options => 
{
    options.Filters.Add<CustomExceptionFilter>();
});

string? connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<CryptoAppDbContext>(options =>
{
    options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString));
});

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddHttpContextAccessor();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30); // Postavite vremenski period sesije
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

builder.Services.AddScoped<IUserRepository, UserRepository>();
//builder.Services.AddTransient<IUserRepository, UserRepository>();
//builder.Services.AddSingleton<IUserRepository, UserRepository>();

//builder.Services.Configure<Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions>(options =>
//{
//    options.Listen(IPAddress.Any, 5002); // Promenite port prema vašem izboru
//}); 

builder.Services.AddCors(options =>
{
    options.AddPolicy("CorsPolicy",
        builder => builder.AllowAnyOrigin()
                          .AllowAnyMethod()
                          .AllowAnyHeader()
                          // .SetIsOriginAllowed(origin => true)
                          );
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.UseSession(); // Dodajte ovo prije UseEndpoints

app.MapControllers();

app.UseCors("CorsPolicy");

app.Run();