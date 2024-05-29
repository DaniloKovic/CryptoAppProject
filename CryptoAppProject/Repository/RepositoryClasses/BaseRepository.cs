using CryptoAppProject.Repository.RepositoryInterfaces;
using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;

namespace CryptoAppProject.Repository.RepositoryClasses
{
    public class BaseRepository<T> : IBaseRepository<T> where T : class
    {
        // private readonly IConfiguration _configuration;
        // private string connectionString = Configuration.GetConnectionString("DefaultConnection");
        protected readonly CryptoAppDbContext _context;

        public BaseRepository(CryptoAppDbContext context) 
        {
            _context = context;
        }

        public async Task<T?> Get(int id)
        {
            return await _context.Set<T>().FindAsync(id);
        }

        public async Task<T?> Get(string id)
        {
            return await _context.Set<T>().FindAsync(id);
        }

        public async Task<IEnumerable<T>> GetAll()
        {
            return await _context.Set<T>().ToListAsync();
        }

        public async Task<IEnumerable<T>> GetAllNoTracking()
        {
            return await _context.Set<T>().AsNoTracking().ToListAsync();
        }

        public async Task<int> InsertNewItemAsync(T record)
        {
            // _context.Set<T>().AddAsync(record);
            _context.Set<T>()?.AddAsync(record);
            int result = await _context.SaveChangesAsync();
            return result;
        }

        public async void InsertNewRangeItemsAsync(IEnumerable<T> record)
        {
            /// _context.Set<T>().AddRange(record);
            await _context.Set<T>().AddRangeAsync(record);
            await _context.SaveChangesAsync();
        }

        public async Task DeleteItemAsync(int id)
        {
            _context.Remove(id);
            _context.SaveChanges();
        }

        public async Task DeleteItemAsync(T item)
        {
            throw new NotImplementedException();
        }

        public async Task DeleteRangeItemsAsync(IEnumerable<T> items)
        {
            throw new NotImplementedException();
        }

        public async Task<IEnumerable<T>> FindByAsync(Expression<Func<T, bool>> predicate)
        {
            return _context.Set<T>().Where(predicate);
        }

        public async Task<int> UpdateItemAsync(T item)
        {
            _context.Set<T>().Update(item);
            return _context.SaveChanges();
        }

        public void UpdateRangeItemsAsync(IEnumerable<T> record)
        {
            throw new NotImplementedException();
        }
    }
}
