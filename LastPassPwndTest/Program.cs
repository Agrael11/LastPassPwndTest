using CLIHelper;

namespace LastPassPwndTest
{
    internal class Program
    {
#if !DEBUG
        private readonly static string uri = "https://api.pwnedpasswords.com/range/";
#endif
        private static ConsoleColor defaultColor = ConsoleColor.White;

        static void Main(string[] args)
        {   
            defaultColor = Console.ForegroundColor;

            var entries = ReadEntries("C:\\Users\\olive\\Downloads\\lastpass_vault_export.csv"); //TODO CHANGE
            ParseEntires(entries, out var safeEntries, out var unsafeEntries);

            while (InteractivePrompt(safeEntries, unsafeEntries)) ;
        }

        private static void ParseEntires(List<PasswordEntry> inputEntries, out List<PasswordEntry> safeEntries, out List<PasswordEntry> unsafeEntries)
        {
            safeEntries = [];
            unsafeEntries = [];

            var lines = new List<string>();
            for (int i = 0; i < inputEntries.Count; i++)
            {
                Console.Clear();
                Console.CursorTop = 0;
                Console.WriteLine($"Checked {i}/{inputEntries.Count}");
                foreach (var line in lines)
                {
                    Console.WriteLine(line);
                }

                var entry = inputEntries[i];
                Console.Write($"Checking {entry}...");
                var sha1 = entry.GetSHA1Password();
                var sha1start = sha1[..5];
                var shas = GetSHAs(sha1start);
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
                if (lines.Count > Console.WindowHeight - 5)
                {
                    lines.RemoveAt(0);
                }
            }
        }

        private static bool InteractivePrompt(List<PasswordEntry> safeEntries, List<PasswordEntry> unsafeEntries)
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
            var c = Choice();
            if (c == 1)
            {
                foreach (var entry in safeEntries)
                {
                    WriteEntry(entry, true, false);
                }
                return true;
            }
            else if (c == 2)
            {
                foreach (var entry in unsafeEntries)
                {
                    WriteEntry(entry, false, false);
                }
                return true;
            }
            else if (c == 3)
            {
                foreach (var entry in unsafeEntries)
                {
                    WriteEntry(entry, false, true);
                }
                return true;
            }
            if (c == 4)
            {
                return false;
            }
            return true;
        }

        private static List<PasswordEntry> ReadEntries(string path)
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
            return entries;
        }

        private static int Choice()
        {
            Console.WriteLine("What do you want to do?");
            Console.WriteLine("1) Show Safe Entries");
            Console.WriteLine("2) Show Unsafe Entries");
            Console.WriteLine("3) Show Unsafe Entries with password");
            Console.WriteLine("4) Exit");
            var choice = Console.ReadKey(true);
            if (choice.KeyChar >= '0' && choice.KeyChar <= '9')
            {
                return (int)(choice.KeyChar - '0');
            }
            return -1;
        }

        private static void RegisterArgs()
        {
            Config.FullName = "LastPass - HaveIBeenPwned analyzer";
            Config.Version = "0.1.0";
            Config.License = "Copyright (C) 2025 Oliver Neuschl\r\nThis software uses GPL 3.0 License";
            Config.HelpHeader = "LastPass - HaveIBeenPwned analyzer";
            Config.ErrorOnUnkownArguments = false;
            Arguments.RegisterArgument("inputfile", new ArgumentDefinition(ArgumentType.String, "inputfile", "if", "Selects input file (cannot be used with -i)", "File Name"));
            Arguments.RegisterArgument("outputfile", new ArgumentDefinition(ArgumentType.String, "outputfile", "of", "Selects Output File", "File Name"));
            Arguments.RegisterArgument("howto", new ArgumentDefinition(ArgumentType.Flag, "instructions", "i", "Shows instructions on retrieval of lastpass vault export"));
            Arguments.RegisterArgument("showall", new ArgumentDefinition(ArgumentType.Flag, "showall", "a", "Shows all Entries"));
            Arguments.RegisterArgument("showsafe", new ArgumentDefinition(ArgumentType.Flag, "showsafe", "s", "Shows safe Entries only"));
            Arguments.RegisterArgument("showpwned", new ArgumentDefinition(ArgumentType.Flag, "showpwned", "p", "Shows possibly pwned Entries only"));
            Arguments.RegisterArgument("help", new ArgumentDefinition(ArgumentType.Flag, "help", "h", "Shows This Information"));
            Arguments.RegisterArgument("version", new ArgumentDefinition(ArgumentType.Flag, "version", "v", "Shows Version"));
            Config.HelpExample = "-if \"lastpastexport.csv\" -of \"output.txt\"";
        }

        private static string WriteEntry(PasswordEntry entry, bool safe, bool showpassword)
        {
            var result = $"{entry} ";
            Console.ForegroundColor = defaultColor;
            Console.Write($"{entry} ");
            if (showpassword)
            {
                result += $"- {entry.Password} ";
                Console.Write("- ");
                Console.ForegroundColor = ConsoleColor.Blue;
                Console.Write($"{entry.Password} ");
            }

            if (safe)
            {
                result += $"[SAFE]";
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[SAFE]");
            }
            else
            {
                result += $"[POSSIBLY PWNED]";
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[POSSIBLY PWNED]");
            }
            return result;
        }

        private static List<string> GetSHAs(string sha1start)
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
