using CryptoAppProject.Model;

namespace CryptoAppProject.Repository.RepositoryInterfaces
{
    public interface IUserRepository : IBaseRepository<User>
    {
        Task<User?> GetByUsername(string username);
        Task<bool> LogInUserCheck(string username, string password);
    }
}
