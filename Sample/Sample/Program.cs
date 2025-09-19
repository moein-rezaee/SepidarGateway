
using System;
using System.Text;

using Sample.Base;
using Sample.Services;

namespace Sample
{
    class Program
    {
        const string BASE_URL = "http://localhost:7373/";
        const string GENERATION_VERSION = "101";
        const string REGISTRATION__CODE = "10053ad1";
        const string USERNAME = "shop";
        const string PASSWORD = "1";

        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.Unicode;

            try
            {
                var config = new Configuration(BASE_URL, GENERATION_VERSION);

                var device = new DevicesService(config, REGISTRATION__CODE);
                device.Register();
                Console.WriteLine($"Device Name: {device.DeviceName}");

                var user = new UsersService(device);
                user.Login(USERNAME, PASSWORD);
                Console.WriteLine($"User Title: {user.UserTile}");

                var itemService = new ItemsService(user);
                var items = itemService.GetItems();
                Console.WriteLine("Items:");
                foreach (var item in items)
                {
                    Console.WriteLine($"Item {item.ItemID:000}: {item.Code}-{item.Title}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }
        }
    }
}
