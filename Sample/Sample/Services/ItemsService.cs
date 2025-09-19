using System.Collections.Generic;
using System.Net.Http;

using Sample.DTO;
using Sample.Helper;

namespace Sample.Services
{
    class ItemsService
    {
        private readonly UsersService user;

        public ItemsService(UsersService user)
        {
            this.user = user;
        }

        public IEnumerable<ItemResponse> GetItems()
        {
            var url = user.GetAbsoluteUrl("/api/items");

            using (var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Clear();
                client.DefaultRequestHeaders.AddRange(user.CreateHeaders());
                return client.Get<IEnumerable<ItemResponse>>(url);
            }
        }
    }
}
