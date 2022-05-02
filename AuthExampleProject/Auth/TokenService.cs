using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthExampleProject.Auth
{
    public interface ITokenService
    {
        AuthTokenResponse Authenticate(AuthTokenRequest model);
    }
}
