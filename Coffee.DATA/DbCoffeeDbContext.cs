using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Coffee.DATA.Models;

namespace Coffee.DATA
{
    public class DbCoffeeDbContext : DbContext
    {
        public DbCoffeeDbContext() { }
        public DbCoffeeDbContext(DbContextOptions<DbCoffeeDbContext> options) : base(options) { }
        public DbSet<Category> Categories { get; set; }
        public DbSet<New> News { get; set; }
        public DbSet<Order> Orders { get; set; }
        public DbSet<OrderDetail> OrderDetails { get; set; }
        public DbSet<Product> Products { get; set; }
        public DbSet<ProductImage> ProductImages { get; set; }
        public DbSet<Role> Roles { get; set; }
        public DbSet<User> Users { get; set; }
        public DbSet<Contact> Contact { get; set; }
        public DbSet<Book> Book { get; set; }
        public DbSet<Review> Reviews { get; set; }
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", true, true);
            IConfigurationRoot configuration = builder.Build();
            optionsBuilder.UseSqlServer(configuration.GetConnectionString("DefaultConnection"));
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<New>(entity =>
            {
                entity.ToTable("New");

                entity.Property(e => e.UserId).HasColumnName("UserId");

                entity.HasOne(d => d.User).WithMany(p => p.News)
                    .HasForeignKey(d => d.UserId)
                    .HasConstraintName("FK_New_User");
            });
            modelBuilder.Entity<User>(entity =>
            {
                entity.ToTable("User");

                entity.Property(e => e.RoleId).HasColumnName("RoleId");

                entity.HasOne(d => d.Role).WithMany(p => p.Users)
                    .HasForeignKey(d => d.RoleId)
                    .HasConstraintName("FK_User_Role");
            });

            modelBuilder.Entity<Order>(entity =>
            {
                entity.ToTable("Order");
                entity.Property(e => e.UserId).HasColumnName("UserId");

                entity.HasOne(d => d.User).WithMany(p => p.Orders)
                    .HasForeignKey(d => d.UserId)
                    .HasConstraintName("FK_User_Order");

            });

            modelBuilder.Entity<OrderDetail>(entity =>
            {
                entity.ToTable("OrderDetail");

                entity.Property(e => e.OrderId).HasColumnName("OrderId");
                entity.Property(e => e.ProductId).HasColumnName("ProductId");

                entity.HasOne(d => d.Order).WithMany(p => p.OrderDetails)
                    .HasForeignKey(d => d.OrderId)
                    .HasConstraintName("FK_OrderDetail_Order");

                entity.HasOne(d => d.Product).WithMany(p => p.OrderDetails)
                    .HasForeignKey(d => d.ProductId)
                    .HasConstraintName("FK_OrderDetail_Product");
            });

            modelBuilder.Entity<Product>(entity =>
            {
                entity.ToTable("Product");
                entity.Property(e => e.Price).HasColumnType("decimal(18, 0)");
                entity.Property(e => e.DiscountPrice).HasColumnType("decimal(18, 0)");
                entity.Property(e => e.CategoryId).HasColumnName("CategoryId");

                entity.HasOne(d => d.Category).WithMany(p => p.Products)
                    .HasForeignKey(d => d.CategoryId)
                    .HasConstraintName("FK_Product_Category");
            });
            modelBuilder.Entity<ProductImage>(entity =>
            {
                entity.ToTable("ProductImage");

                entity.HasOne(d => d.Product).WithMany(p => p.ProductImages)
                    .HasForeignKey(d => d.ProductId)
                    .HasConstraintName("FK_ProductImage_Product");
            });
            modelBuilder.Entity<Review>(entity =>
            {
                entity.ToTable("Reviews"); // Đặt tên bảng là "Reviews"

                // Mối quan hệ 1-n: Mỗi đánh giá (Review) chỉ đề cập đến một sản phẩm (Product), mỗi sản phẩm có thể có nhiều đánh giá
                entity.HasOne(r => r.Product)
                    .WithMany(p => p.Reviews) // Thuộc tính Reviews trong Product là một ICollection<Review>
                    .HasForeignKey(r => r.ProductId) // Sử dụng ProductId trong Review làm khóa ngoại
                    .HasConstraintName("FK_Review_Product"); // Đặt tên ràng buộc khóa ngoại là "FK_Review_Product"

                // Mối quan hệ n-1: Mỗi đánh giá (Review) đều được liên kết với một người dùng (User), một người dùng có thể có nhiều đánh giá
                entity.HasOne(r => r.User)
                    .WithMany(u => u.Reviews) // Thuộc tính Reviews trong User là một ICollection<Review>
                    .HasForeignKey(r => r.UserId) // Sử dụng UserId trong Review làm khóa ngoại
                    .HasConstraintName("FK_Review_User"); // Đặt tên ràng buộc khóa ngoại là "FK_Review_User"
            });

        }
    }
}
