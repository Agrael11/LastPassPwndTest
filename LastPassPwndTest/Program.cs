using System.Drawing;
using System.Net;
using System.Runtime.CompilerServices;

namespace LastPassPwndTest
{
    internal class Program
    {
        static string path = "C:\\Users\\olive\\Downloads\\lastpass_vault_export.csv";
        private readonly static string uri = "https://api.pwnedpasswords.com/range/";
        private static ConsoleColor defaultColor = ConsoleColor.White;

        static void Main(string[] args)
        {          
            var entries = new List<PasswordEntry>();
            using var parser = new Microsoft.VisualBasic.FileIO.TextFieldParser(path);
            parser.SetDelimiters(",");
            parser.HasFieldsEnclosedInQuotes = true;
            parser.ReadFields();
            while (!parser.EndOfData)
            {
                var fields = parser.ReadFields();
                if (fields is null) continue;
                var entry = new PasswordEntry(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7]);
                entries.Add(entry);
            }

            defaultColor = Console.ForegroundColor;

            var safeEntries = new List<PasswordEntry>();
            var unsafeEntries = new List<PasswordEntry>();

            var lines = new List<string>(); 
            for (int i = 0; i < entries.Count; i++)
            {
                Console.Clear();
                Console.CursorTop = 0;
                Console.WriteLine($"Checked {i}/{entries.Count}");
                foreach (var line in lines)
                {
                    Console.WriteLine(line);
                }

                var entry = entries[i];
                Console.Write($"Checking {entry}...");
                var sha1 = entry.getSHA1Password();
                var sha1start = sha1[..5];
                var shas = getSHAs(sha1start);
                if (shas.Contains(sha1))
                {
                    unsafeEntries.Add(entry);
                }
                else
                {
                    safeEntries.Add(entry);
                }

                Console.WriteLine($" [DONE]");
                lines.Add($"Checking {entry}... [DONE]");
                if (lines.Count > Console.WindowHeight-5)
                {
                    lines.RemoveAt(0);
                }
            }

            var c = -1;
            while (c == -1)
            {
                Console.Write("Found ");
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write($"{safeEntries.Count} safe entries");
                Console.ForegroundColor = defaultColor;
                Console.Write(" and ");
                Console.ForegroundColor = ConsoleColor.Red;
                Console.Write($"{unsafeEntries.Count} unsafe entries");
                Console.ForegroundColor = defaultColor;
                Console.WriteLine();
                c = Choice();
                if (c == 1)
                {
                    foreach (var entry in safeEntries)
                    {
                        WriteEntry(entry, true, false);
                    }
                    c = -1;
                }
                else if (c == 2)
                {
                    foreach (var entry in unsafeEntries)
                    {
                        WriteEntry(entry, false, false);
                    }
                    c = -1;
                }
                else if (c == 3)
                {
                    foreach (var entry in unsafeEntries)
                    {
                        WriteEntry(entry, false, true);
                    }
                    c = -1;
                }
            }
        }

        private static int Choice()
        {
            Console.WriteLine("What do you want to do?");
            Console.WriteLine("1) Show Safe Entries");
            Console.WriteLine("2) Show Unsafe Entries");
            Console.WriteLine("2) Show Unsafe Entries with password");
            Console.WriteLine("3) Exit");
            var choice = Console.ReadKey(true);
            if (choice.KeyChar >= '0' && choice.KeyChar <= '9')
            {
                return (int)(choice.KeyChar - '0');
            }
            return -1;
        }

        private static void WriteEntry(PasswordEntry entry, bool safe, bool showpassword)
        {
            Console.ForegroundColor = defaultColor;
            Console.Write($"{entry} ");
            if (showpassword)
            {
                Console.Write("- ");
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.Write($"{entry.Password} ");
            }

            if (safe)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[SAFE]");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[POSSIBLY PWNED]");
            }
        }

        private static List<string> getSHAs(string sha1start)
        {
            var list = new List<string>();
#if DEBUG
            Task.Delay(50).Wait();
#else
            var client = new HttpClient();
            var resultTask = client.GetStringAsync($"{uri}{sha1start}");
            resultTask.Wait();
            var results = resultTask.Result.Split('\n');
            foreach (var result in results)
            {
                var hash = result.Trim('\r').Split(':')[0];
                list.Add(sha1start + hash);
            }
#endif
            return list;
        }
    }
}
