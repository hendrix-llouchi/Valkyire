using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using CodeShield.Data;
using CodeShield.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddHttpClient<IGitHubService, GitHubService>();
builder.Services.AddHttpClient<IOsvService, OsvService>();
builder.Services.AddHttpClient<IAiExplanationService, AiExplanationService>();
builder.Services.AddTransient<ICodePatternScanner, CodePatternScanner>();


// Register ApplicationDbContext
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") 
    ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// Register ASP.NET Identity services
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    // Password settings
    options.Password.RequiredLength = 8;
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Configure application cookie settings
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromDays(14);
    options.SlidingExpiration = true;
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

// Seed default user and run migrations
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        // Migrate database
        var dbContext = services.GetRequiredService<ApplicationDbContext>();
        dbContext.Database.Migrate();

        var userManager = services.GetRequiredService<UserManager<IdentityUser>>();
        var defaultUsername = "admin";
        var defaultUser = userManager.FindByNameAsync(defaultUsername).Result;
        if (defaultUser == null)
        {
            var user = new IdentityUser { UserName = defaultUsername, EmailConfirmed = true };
            var result = userManager.CreateAsync(user, "Admin123!").Result;
            if (result.Succeeded)
            {
                Console.WriteLine("Successfully seeded default user: admin / Admin123!");
            }
            else
            {
                Console.WriteLine("Error seeding user: " + string.Join(", ", result.Errors.Select(e => e.Description)));
            }
        }
    }
    catch (Exception ex)
    {
        Console.WriteLine("An error occurred while seeding the database: " + ex.Message);
    }
}

app.Run();


