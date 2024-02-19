using CryptoAppProject.Model;
using CryptoAppProject.Model.Requests;
using System.Linq.Expressions;

namespace CryptoAppProject.Repository.RepositoryInterfaces
{
    public interface IUserRepository : IBaseRepository<User>
    {
        Task<User?> GetByUsername(string username);
        Task<bool> LogInUserCheck(string username, string password);
    }
}
