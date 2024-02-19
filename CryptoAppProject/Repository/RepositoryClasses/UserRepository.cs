using CryptoAppProject.Helper;
using CryptoAppProject.Model;
using CryptoAppProject.Repository.RepositoryInterfaces;
using Microsoft.EntityFrameworkCore;
using Org.BouncyCastle.Security;
using System.Linq.Expressions;

namespace CryptoAppProject.Repository.RepositoryClasses
{
    public class UserRepository : BaseRepository<User>, IUserRepository
    {
        // public UserRepository() : base() { }
        public UserRepository(CryptoAppDbContext dbContext) : base(dbContext)
        {
        }

        public async Task<User?> GetByUsername(string username)
        {
            return await _context.Set<User>().FirstOrDefaultAsync(u => u.Username.Equals(username));
        }

        public async Task<bool> LogInUserCheck(string username, string password)
        {
            User? user = await _context.Set<User>().FirstOrDefaultAsync(u => u.Username.Equals(username));
            if(user == null) { 
                return false; 
            }
            if(user.PasswordHash.Equals(CryptoExtensionsClass.HashPassword(password, user.Salt))) {
                return true;
            }
            return false;
        }
    }
}
