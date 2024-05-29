using CryptoAppProject.Model;
using CryptoAppProject.Repository.RepositoryInterfaces;

namespace CryptoAppProject.Repository.RepositoryClasses
{
    public class LogActivityRepository : BaseRepository<LogActivity>, ILogActivityRepository
    {
        // public UserRepository() : base() { }
        public LogActivityRepository(CryptoAppDbContext dbContext) 
            : base(dbContext)
        {
        }

        //public async Task<LogActivity?> CreateLog(string obj)
        //{
        //    _context.Set<LogActivity>().InsertNewItemAsync()
        //}

    }
}
