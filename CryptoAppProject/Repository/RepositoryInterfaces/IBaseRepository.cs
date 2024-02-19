using System.Linq.Expressions;

namespace CryptoAppProject.Repository.RepositoryInterfaces
{
    public interface IBaseRepository<T>
    {
        Task<IEnumerable<T>> GetAll();
        Task<IEnumerable<T>> GetAllNoTracking();
        Task<T?> Get(int id);
        Task<T?> Get(string id);
        Task<IEnumerable<T>> FindByAsync(Expression<Func<T, bool>> predicate);

        Task<int> InsertNewItemAsync(T record);
        void InsertNewRangeItemsAsync(IEnumerable<T> record);
        Task<int> UpdateItemAsync(T record);
        void UpdateRangeItemsAsync(IEnumerable<T> record);

        Task DeleteItemAsync(int id);
        Task DeleteItemAsync(T item);
        Task DeleteRangeItemsAsync(IEnumerable<T> items);
    }
}
