using Coffee.DATA;
using Microsoft.AspNetCore.Authentication.Cookies;
using Coffee.DATA.Repository;
using Coffee.DATA.Common;
using Microsoft.AspNetCore.SignalR;
using Coffee.DATA.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Hosting;


namespace Coffee.WebUI
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddControllersWithViews();
            builder.Services.AddScoped(typeof(DbCoffeeDbContext));
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            })
                .AddCookie(options =>
                {
                    options.LoginPath = "/Login/Index";
                    options.AccessDeniedPath = "/Login/Index"; // Đường dẫn đến trang bị từ chối truy cập
                    options.Cookie.HttpOnly = true;
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(60); // Thời gian hết hạn của cookie là 60 phút
                    options.SlidingExpiration = true; // Kích hoạt thời hạn trượt
                })
                .AddGoogle(googleOptions =>
                {
                    googleOptions.ClientId = "42557447431-n5q58cmqp5baqubhi07qshub2m03veoj.apps.googleusercontent.com";
                    googleOptions.ClientSecret = "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";
                });
            builder.Services.AddScoped(typeof(IRepository<>), typeof(Repository<>));
            builder.Services.AddHttpContextAccessor();
            builder.Services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(20); // Thời gian chờ không hoạt động là 20 phút
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true; // Đảm bảo rằng cookie của session là cần thiết cho ứng dụng
            });
            builder.Services.AddDistributedMemoryCache();
            builder.Services.AddHttpClient();
            builder.Services.AddAutoMapper(typeof(Program));
            //builder.Services.AddControllersWithViews();
            builder.Services.AddSignalR(options =>
            {
                options.ClientTimeoutInterval = TimeSpan.FromSeconds(30); // Đặt thời gian chờ kết nối là 30 giây (ví dụ)
                //options.KeepAliveInterval = TimeSpan.FromSeconds(15); // Đặt thời gian giữa các tin nhắn keep-alive là 15 giây (ví dụ)
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
            app.UseStaticFiles();
            app.UseSession(); // Kích hoạt việc sử dụng Session
            app.UseRouting();
            app.Use(async (context, next) =>
            {
                await next();

                // Nếu không tìm thấy trang
                if (context.Response.StatusCode == 404 && !context.Response.HasStarted)
                {
                    // Thiết lập trạng thái response
                    context.Response.StatusCode = 404;

                    // Gửi thông báo "That page can’t be found."
                    context.Response.Redirect("/Home/Error");
                }
            });
            app.UseAuthorization();
            ConfigureEndpoints(app);
            //app.MapAreaControllerRoute(
            //    name: "Admin",
            //    areaName: "Admin",
            //    pattern: "Admin/{controller=Home}/{action=Index}/{id?}"
            //    );
            //app.MapControllerRoute(
            //    name: "default",
            //    pattern: "{controller=Home}/{action=Index}/{id?}");
            app.Run();
        }
        private static void ConfigureEndpoints(IApplicationBuilder app)
        {
            app.UseEndpoints(endpoints =>
            {
                
                endpoints.MapControllerRoute(
                    name: "login",
                    pattern: "login",
                    defaults: new { controller = "Login", action = "Index" });
                endpoints.MapControllerRoute(
                    name: "login",
                    pattern: "register",
                    defaults: new { controller = "Login", action = "Register" });
                endpoints.MapControllerRoute(
                    name: "shop",
                    pattern: "cua-hang",
                    defaults: new { controller = "Product", action = "Index" });
                endpoints.MapControllerRoute(
                    name: "reservation",
                    pattern: "dat-ban",
                    defaults: new { controller = "Reservation", action = "Index" });
                endpoints.MapControllerRoute(
                    name: "introduce",
                    pattern: "gioi-thieu",
                    defaults: new { controller = "Home", action = "Introduce" });
                endpoints.MapControllerRoute(
                    name: "reservation",
                    pattern: "dat-ban",
                    defaults: new { controller = "Home", action = "Reservation" });
                endpoints.MapControllerRoute(
                    name: "contact",
                    pattern: "lien-he",
                    defaults: new { controller = "Home", action = "Contact" });
                endpoints.MapControllerRoute(
                    name: "menu",
                    pattern: "thuc-don",
                    defaults: new { controller = "Menu", action = "Index" });
                endpoints.MapControllerRoute(
                    name: "productdetails",
                    pattern: "san-pham/{url}-{id}",
                    defaults: new { controller = "ProductDetail", action = "Index" }
                );
                endpoints.MapAreaControllerRoute(
                   name: "Admin",
                   areaName: "Admin",
                   pattern: "Admin/{controller=Home}/{action=Index}");
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}");
                endpoints.MapHub<NotificationHub>("/notificationHub");
                //endpoints.MapHub<OrderHub>("/orderHub");
            });
        }
    }
}
