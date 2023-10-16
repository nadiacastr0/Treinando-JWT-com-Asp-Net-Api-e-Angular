using System.Security.Claims;

namespace JwtWebApi.Services
{
    public class UserService : IUserService
    {
        private readonly IHttpContextAccessor _contextAccessor;

        public UserService(IHttpContextAccessor contextAccessor)
        {
            _contextAccessor = contextAccessor;
        }
        public string GetMyName()
        {
            var result = string.Empty;
            if(_contextAccessor != null)
            {
                result = _contextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            }
            return result;
        }
    }
}
