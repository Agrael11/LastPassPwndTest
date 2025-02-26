using System.Security.Cryptography;
using System.Text;

namespace LastPassPwndTest
{
    internal class PasswordEntry(string url, string userName, string password, string totp, string extra, string name, string grouping, string fav)
    {
        public string URL { get; set; } = url;
        public string UserName { get; set; } = userName;
        public string Password { get; set; } = password;
        public string ToTP { get; set; } = totp;
        public string Extra { get; set; } = extra;
        public string Name { get; set; } = name;
        public string Grouping { get; set; } = grouping;
        public string Fav { get; set; } = fav;

        public override string ToString()
        {
            return $"{Name} - {UserName}";
        }


        public string GetSHA1Password()
        {
            var data = SHA1.HashData(Encoding.UTF8.GetBytes(Password));
            var builder = new StringBuilder();
            foreach (var part in data)
            {
                builder.Append(part.ToString("X").PadLeft(2,'0'));
            }
            return builder.ToString();
        }
    }
}
