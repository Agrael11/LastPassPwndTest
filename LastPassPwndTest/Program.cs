using CLIHelper;
using System.Runtime.CompilerServices;
using System.Text;

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
            RegisterArgs();
            Arguments.ParseArguments(args);
            string? inputFile = null;

            if (Arguments.IsArgumentSet("help"))
            {
                Console.WriteLine(Generator.GenerateHelp());
                return;
            }
            if (Arguments.IsArgumentSet("version"))
            {
                Console.WriteLine(Generator.GenerateVersion());
                return;
            }
            if (Arguments.IsArgumentSet("howto"))
            {
                Console.WriteLine("How to export your lastpass vault:");
                Console.WriteLine();
                Console.WriteLine("Step 1: Log in to your LastPass Vault.");
                Console.WriteLine("Step 2: Click Options");
                Console.WriteLine("Step 3: Select Advanced Options");
                Console.WriteLine("Step 4: Select Export");
                Console.WriteLine("Step 5: Save the result as .csv file");
                Console.WriteLine();
                Console.WriteLine("WARNING! THIS WILL EXPORT YOUR PASSWORD IN PLAIN TEXT. KEEP IT SAFE!");
                Console.WriteLine("WE RECOMMEND DELETNG THIS FILE AFTER USING IT!");
                return;
            }

            if (Arguments.IsArgumentSet("inputfile"))
            {
                inputFile = (string)Arguments.GetArgumentData("inputfile");
            }

            defaultColor = Console.ForegroundColor;
            
            if (inputFile is null)
            {
                Console.Write("Please provide an input file path: ");
                inputFile = Console.ReadLine();
            }

            if (inputFile is null)
            {
                Console.Error.Write("No input file provided.");
                return;
            }
            if (!File.Exists(inputFile))
            {
                Console.Error.Write($"[ERROR] File {inputFile} does not exist.");
                return;
            }

            bool outputSet = Arguments.IsArgumentSet("outputfile");

            var entries = ReadEntries(inputFile);
            ParseEntires(entries, out var safeEntries, out var unsafeEntries, !outputSet);
            
            if (!outputSet)
            {
                if (Arguments.IsArgumentSet("showsafe"))
                {
                    ShowEntries(safeEntries, true, Arguments.IsArgumentSet("includepassword"), false);
                }
                else if (Arguments.IsArgumentSet("showpwned"))
                {
                    ShowEntries(unsafeEntries, false, Arguments.IsArgumentSet("includepassword"), false);
                }
                else if (Arguments.IsArgumentSet("showall"))
                {
                    ShowEntries(safeEntries, true, Arguments.IsArgumentSet("includepassword"), false);
                    ShowEntries(unsafeEntries, false, Arguments.IsArgumentSet("includepassword"), false);
                }
                else
                {
                    while (InteractivePrompt(safeEntries, unsafeEntries)) ;
                }
            }
            else
            {
                var outputFile = (string)Arguments.GetArgumentData("outputfile");
                string result;
                if (Arguments.IsArgumentSet("showsafe"))
                {
                    result = ShowEntries(safeEntries, true, Arguments.IsArgumentSet("includepassword"), true);
                }
                else if (Arguments.IsArgumentSet("showpwned"))
                {
                    result = ShowEntries(unsafeEntries, false, Arguments.IsArgumentSet("includepassword"), true);
                }
                else
                {
                    result = ShowEntries(safeEntries, true, Arguments.IsArgumentSet("includepassword"), true);
                    result += ShowEntries(unsafeEntries, false, Arguments.IsArgumentSet("includepassword"), true);
                }
                File.WriteAllText(outputFile, result);
            }

        }

        private static string ShowEntries(List<PasswordEntry> entries, bool safe, bool showPassword, bool verbose)
        {
            var builder = new StringBuilder();
            foreach (var entry in entries)
            {
                builder.AppendLine(WriteEntry(entry, safe, showPassword, verbose));
            }
            return builder.ToString();
        }

        private static string WriteEntry(PasswordEntry entry, bool safe, bool showpassword, bool verbose)
        {
            var result = $"{entry} ";
            if (verbose)
            {
                Console.ForegroundColor = defaultColor;
                Console.Write($"{entry} ");
            }
            if (showpassword)
            {
                result += $"- {entry.Password} ";
                if (verbose)
                {
                    Console.Write("- ");
                    Console.ForegroundColor = ConsoleColor.Blue;
                    Console.Write($"{entry.Password} ");
                }
            }

            if (safe)
            {
                result += $"[SAFE]";
                if (verbose)
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[SAFE]");
                }
            }
            else
            {
                result += $"[POSSIBLY PWNED]";
                if (verbose)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[POSSIBLY PWNED]");
                }
            }
            Console.ForegroundColor = defaultColor;
            return result;
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

        private static void ParseEntires(List<PasswordEntry> inputEntries, out List<PasswordEntry> safeEntries, out List<PasswordEntry> unsafeEntries, bool verbose)
        {
            safeEntries = [];
            unsafeEntries = [];

            var lines = new List<string>();
            for (int i = 0; i < inputEntries.Count; i++)
            {
                var entry = inputEntries[i];


                if (verbose)
                {
                    Console.Clear();
                    Console.CursorTop = 0;
                    Console.WriteLine($"Checked {i}/{inputEntries.Count}");
                    foreach (var line in lines)
                    {
                        Console.WriteLine(line);
                    }
                    Console.Write($"Checking {entry}...");
                }

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

                if (verbose)
                {
                    Console.WriteLine($" [DONE]");
                    lines.Add($"Checking {entry}... [DONE]");
                    if (lines.Count > Console.WindowHeight - 5)
                    {
                        lines.RemoveAt(0);
                    }
                }
            }
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
                ShowEntries(safeEntries, true, false, true);
                return true;
            }
            else if (c == 2)
            {
                ShowEntries(unsafeEntries, false, false, true);
                return true;
            }
            else if (c == 3)
            {
                ShowEntries(unsafeEntries, false, true, true);
                return true;
            }
            if (c == 4)
            {
                return false;
            }
            return true;
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
            Config.Version = "1.0.0";
            Config.License = "Copyright (C) 2025 Oliver Neuschl\r\nThis software uses GPL 3.0 License";
            Config.HelpHeader = "LastPass - HaveIBeenPwned analyzer";
            Config.ErrorOnUnkownArguments = false;
            Arguments.RegisterArgument("inputfile", new ArgumentDefinition(ArgumentType.String, "inputfile", "if", "Selects input file (cannot be used with -i)", "File Name"));
            Arguments.RegisterArgument("outputfile", new ArgumentDefinition(ArgumentType.String, "outputfile", "of", "Selects Output File", "File Name"));
            Arguments.RegisterArgument("howto", new ArgumentDefinition(ArgumentType.Flag, "instructions", "i", "Shows instructions on retrieval of lastpass vault export"));
            Arguments.RegisterArgument("showall", new ArgumentDefinition(ArgumentType.Flag, "showall", "a", "Shows all Entries"));
            Arguments.RegisterArgument("showsafe", new ArgumentDefinition(ArgumentType.Flag, "showsafe", "s", "Shows safe Entries only"));
            Arguments.RegisterArgument("showpwned", new ArgumentDefinition(ArgumentType.Flag, "showpwned", "p", "Shows possibly pwned Entries only"));
            Arguments.RegisterArgument("includepassword", new ArgumentDefinition(ArgumentType.Flag, "includepassword", "ip", "Includes password in the list"));
            Arguments.RegisterArgument("help", new ArgumentDefinition(ArgumentType.Flag, "help", "h", "Shows This Information"));
            Arguments.RegisterArgument("version", new ArgumentDefinition(ArgumentType.Flag, "version", "v", "Shows Version"));
            Config.HelpFooter = "This software compares your exported LastPasss passwords to HaveIBeenPwned database";
            Config.HelpExample = "-if \"lastpastexport.csv\" -of \"output.txt\"";
        }
    }
}
