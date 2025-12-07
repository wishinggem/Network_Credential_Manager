using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Text.Json;
using System.Security.Cryptography;
using System.Text;

namespace Network_Credential_Manager.Pages
{
    public class TableDefinition
    {
        public string Name { get; set; } = "";
        public List<FieldDefinition> Fields { get; set; } = new();
    }

    public class FieldDefinition
    {
        public string Name { get; set; } = "";
        public bool IsEncrypted { get; set; }
        public bool ShowCopyButton { get; set; }
        public bool IsLink { get; set; }
        public string Width { get; set; } = "";
    }

    public class TableRecord
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public Dictionary<string, string> Data { get; set; } = new();
    }

    public class DataStore
    {
        public List<TableDefinition> Tables { get; set; } = new();
        public Dictionary<string, List<TableRecord>> Records { get; set; } = new();
    }

    public class IndexModel : PageModel
    {
        private readonly IConfiguration _config;
        private readonly string _dataPath = Path.Combine("wwwroot", "Data", "data.json");
        private readonly string dataParent = Path.Combine("wwwroot", "Data");
        private readonly string _encryptionKey;
        private readonly string _username;
        private readonly string _password;

        public DataStore DataStore { get; set; } = new();
        public bool IsAuthenticated { get; set; }

        public IndexModel(IConfiguration config)
        {
            _config = config;
            _encryptionKey = _config["ENCRYPTION_KEY"] ?? "default-key-change-me-32chars!";

            if (_encryptionKey == "default-key-change-me-32chars!")
            {
                Console.WriteLine("Warning: Using default encryption key. Could not obtain Key from Enviro");
            }

            _username = _config["USERNAME"] ?? "admin";
            _password = _config["PASSWORD"] ?? "admin";
        }

        [BindProperty]
        public string? LoginError { get; set; }

        public void OnGet()
        {
            if (!CheckAuth())
            {
                IsAuthenticated = false;
                return;
            }
            IsAuthenticated = true;
            LoadData();
        }

        public IActionResult OnGetExport()
        {
            if (!CheckAuth()) return Unauthorized();
            if (!System.IO.File.Exists(_dataPath)) return NotFound();

            var bytes = System.IO.File.ReadAllBytes(_dataPath);
            return File(bytes, "application/json", "data.json");
        }

        public IActionResult OnPostLogin(string username, string password)
        {
            if (username == _username && password == _password)
            {
                Response.Cookies.Append("auth", "true", new CookieOptions { HttpOnly = true });
                return RedirectToPage();
            }
            LoginError = "Invalid username or password";
            IsAuthenticated = false;
            return Page();
        }

        public IActionResult OnPostLogout()
        {
            Response.Cookies.Delete("auth");
            return RedirectToPage();
        }

        public IActionResult OnPostCreateTable([FromBody] TableDefinition table)
        {
            if (!CheckAuth()) return Unauthorized();
            LoadData();
            if (DataStore.Tables.Any(t => t.Name == table.Name))
                return new JsonResult(new { success = false, message = "Table exists" });

            DataStore.Tables.Add(table);
            DataStore.Records[table.Name] = new List<TableRecord>();
            SaveData();
            return new JsonResult(new { success = true });
        }

        public IActionResult OnPostUpdateTable([FromBody] TableUpdateRequest req)
        {
            if (!CheckAuth()) return Unauthorized();
            LoadData();
            var table = DataStore.Tables.FirstOrDefault(t => t.Name == req.OldName);
            if (table != null)
            {
                foreach (var newField in req.NewTable.Fields)
                {
                    var oldField = table.Fields.FirstOrDefault(f => f.Name == newField.Name);
                    if (oldField != null && string.IsNullOrEmpty(newField.Width))
                    {
                        newField.Width = oldField.Width;
                    }
                }

                table.Name = req.NewTable.Name;
                table.Fields = req.NewTable.Fields;
                if (req.OldName != req.NewTable.Name && DataStore.Records.ContainsKey(req.OldName))
                {
                    DataStore.Records[req.NewTable.Name] = DataStore.Records[req.OldName];
                    DataStore.Records.Remove(req.OldName);
                }
                SaveData();
            }
            return new JsonResult(new { success = true });
        }

        public IActionResult OnPostDeleteTable(string tableName)
        {
            if (!CheckAuth()) return Unauthorized();
            LoadData();
            DataStore.Tables.RemoveAll(t => t.Name == tableName);
            DataStore.Records.Remove(tableName);
            SaveData();
            return new JsonResult(new { success = true });
        }

        public IActionResult OnPostCreateRecord([FromBody] RecordRequest req)
        {
            if (!CheckAuth()) return Unauthorized();
            LoadData();
            var table = DataStore.Tables.FirstOrDefault(t => t.Name == req.TableName);
            if (table == null) return NotFound();

            // FIXED: Removed manual Encrypt() loop here. 
            // Data is added as plain text, then EncryptAllFields() in SaveData() handles it.
            var record = new TableRecord { Data = req.Data };

            if (!DataStore.Records.ContainsKey(req.TableName))
                DataStore.Records[req.TableName] = new();

            DataStore.Records[req.TableName].Add(record);
            SaveData();
            return new JsonResult(new { success = true, id = record.Id });
        }

        public IActionResult OnPostUpdateRecord([FromBody] RecordUpdateRequest req)
        {
            if (!CheckAuth()) return Unauthorized();
            LoadData();
            var table = DataStore.Tables.FirstOrDefault(t => t.Name == req.TableName);
            if (table == null) return NotFound();

            var records = DataStore.Records[req.TableName];
            var record = records.FirstOrDefault(r => r.Id == req.RecordId);
            if (record == null) return NotFound();

            // FIXED: Removed manual Encrypt() loop here.
            record.Data = req.Data;

            SaveData();
            return new JsonResult(new { success = true });
        }

        public IActionResult OnPostDeleteRecord(string tableName, string recordId)
        {
            if (!CheckAuth()) return Unauthorized();
            LoadData();
            if (DataStore.Records.ContainsKey(tableName))
            {
                DataStore.Records[tableName].RemoveAll(r => r.Id == recordId);
                SaveData();
            }
            return new JsonResult(new { success = true });
        }

        public IActionResult OnPostReorderTables([FromBody] List<string> tableNames)
        {
            if (!CheckAuth()) return Unauthorized();
            LoadData();

            var newOrder = new List<TableDefinition>();
            foreach (var name in tableNames)
            {
                var t = DataStore.Tables.FirstOrDefault(x => x.Name == name);
                if (t != null) newOrder.Add(t);
            }

            foreach (var t in DataStore.Tables)
            {
                if (!newOrder.Contains(t)) newOrder.Add(t);
            }

            DataStore.Tables = newOrder;
            SaveData();
            return new JsonResult(new { success = true });
        }

        public IActionResult OnPostReorderRecords([FromBody] ReorderRecordsRequest req)
        {
            if (!CheckAuth()) return Unauthorized();
            LoadData();

            if (DataStore.Records.ContainsKey(req.TableName))
            {
                var currentRecords = DataStore.Records[req.TableName];
                var newOrder = new List<TableRecord>();

                foreach (var id in req.RecordIds)
                {
                    var r = currentRecords.FirstOrDefault(x => x.Id == id);
                    if (r != null) newOrder.Add(r);
                }

                foreach (var r in currentRecords)
                {
                    if (!newOrder.Contains(r)) newOrder.Add(r);
                }

                DataStore.Records[req.TableName] = newOrder;
                SaveData();
            }

            return new JsonResult(new { success = true });
        }

        public IActionResult OnPostUpdateColumnWidth([FromBody] UpdateWidthRequest req)
        {
            if (!CheckAuth()) return Unauthorized();
            LoadData();

            var table = DataStore.Tables.FirstOrDefault(t => t.Name == req.TableName);
            if (table != null)
            {
                var field = table.Fields.FirstOrDefault(f => f.Name == req.FieldName);
                if (field != null)
                {
                    field.Width = req.Width;
                    // When we save here, SaveData() will now re-encrypt all records,
                    // preventing the plain-text bug you were seeing.
                    SaveData();
                }
            }
            return new JsonResult(new { success = true });
        }

        private bool CheckAuth()
        {
            return Request.Cookies.ContainsKey("auth") && Request.Cookies["auth"] == "true";
        }

        private void LoadData()
        {
            if (System.IO.File.Exists(_dataPath))
            {
                try
                {
                    var json = System.IO.File.ReadAllText(_dataPath);
                    DataStore = JsonSerializer.Deserialize<DataStore>(json) ?? new DataStore();
                    DecryptAllFields();
                }
                catch
                {
                    DataStore = new DataStore();
                }
            }
        }

        private void SaveData()
        {
            if (!Directory.Exists(dataParent))
            {
                Directory.CreateDirectory(dataParent);
            }

            // FIXED: Always encrypt memory state before writing to disk
            EncryptAllFields();

            var json = JsonSerializer.Serialize(DataStore, new JsonSerializerOptions { WriteIndented = true });
            System.IO.File.WriteAllText(_dataPath, json);
        }

        private void DecryptAllFields()
        {
            foreach (var table in DataStore.Tables)
            {
                if (!DataStore.Records.ContainsKey(table.Name)) continue;
                foreach (var record in DataStore.Records[table.Name])
                {
                    foreach (var field in table.Fields.Where(f => f.IsEncrypted))
                    {
                        if (record.Data.ContainsKey(field.Name))
                        {
                            var val = Decrypt(record.Data[field.Name]);
                            // Only update if decryption succeeded
                            if (val != "[Decryption Failed]" && val != null)
                            {
                                record.Data[field.Name] = val;
                            }
                        }
                    }
                }
            }
        }

        // FIXED: New helper to handle encryption before save
        private void EncryptAllFields()
        {
            foreach (var table in DataStore.Tables)
            {
                if (!DataStore.Records.ContainsKey(table.Name)) continue;
                foreach (var record in DataStore.Records[table.Name])
                {
                    foreach (var field in table.Fields.Where(f => f.IsEncrypted))
                    {
                        if (record.Data.ContainsKey(field.Name))
                        {
                            // We encrypt whatever is in memory (which should be plain text from LoadData)
                            record.Data[field.Name] = Encrypt(record.Data[field.Name]);
                        }
                    }
                }
            }
        }

        private string Encrypt(string text)
        {
            if (string.IsNullOrEmpty(text)) return "";
            try
            {
                using var aes = Aes.Create();
                aes.Key = SHA256.HashData(Encoding.UTF8.GetBytes(_encryptionKey));
                aes.GenerateIV();

                using var encryptor = aes.CreateEncryptor();
                var plainBytes = Encoding.UTF8.GetBytes(text);
                var encryptedBytes = encryptor.TransformFinalBlock(plainBytes, 0, plainBytes.Length);

                var result = new byte[aes.IV.Length + encryptedBytes.Length];
                Buffer.BlockCopy(aes.IV, 0, result, 0, aes.IV.Length);
                Buffer.BlockCopy(encryptedBytes, 0, result, aes.IV.Length, encryptedBytes.Length);

                return Convert.ToBase64String(result);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Encryption failed: {ex.Message}");
                throw;
            }
        }

        private string Decrypt(string encryptedText)
        {
            if (string.IsNullOrEmpty(encryptedText)) return "";
            try
            {
                // Basic Base64 validation
                if (encryptedText.Length % 4 != 0) return null;

                var fullCipher = Convert.FromBase64String(encryptedText);

                using var aes = Aes.Create();
                aes.Key = SHA256.HashData(Encoding.UTF8.GetBytes(_encryptionKey));

                if (fullCipher.Length < aes.IV.Length) return "";

                var iv = new byte[aes.IV.Length];
                var cipher = new byte[fullCipher.Length - iv.Length];

                Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
                Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, cipher.Length);

                aes.IV = iv;

                using var decryptor = aes.CreateDecryptor();
                var decryptedBytes = decryptor.TransformFinalBlock(cipher, 0, cipher.Length);

                return Encoding.UTF8.GetString(decryptedBytes);
            }
            catch (FormatException e)
            {
                Console.WriteLine($"Data Corruption: The input '{encryptedText}' is not valid Base64.");
                Console.WriteLine($"Attempted to decrypt: {encryptedText}");
                Console.WriteLine($"Message: {e.Message}");
                Console.WriteLine($"InnerException: {e.InnerException}");
                Console.WriteLine($"Stack Trace: {e.StackTrace}");
                return "[Failed To Decrypt]";
            }
            catch (CryptographicException e)
            {
                Console.WriteLine("Decryption failed: Wrong Key or Corrupted Data.");
                Console.WriteLine($"Attempted to decrypt: {encryptedText}");
                Console.WriteLine($"Message: {e.Message}");
                Console.WriteLine($"InnerException: {e.InnerException}");
                Console.WriteLine($"Stack Trace: {e.StackTrace}");
                return "[Failed To Decrypt]";
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error Decrypting");
                Console.WriteLine($"Attempted to decrypt: {encryptedText}");
                Console.WriteLine($"Message: {e.Message}");
                Console.WriteLine($"InnerException: {e.InnerException}");
                Console.WriteLine($"Stack Trace: {e.StackTrace}");
                return "[Failed To Decrypt]";
            }
        }
    }

    public class TableUpdateRequest
    {
        public string OldName { get; set; } = "";
        public TableDefinition NewTable { get; set; } = new();
    }

    public class RecordRequest
    {
        public string TableName { get; set; } = "";
        public Dictionary<string, string> Data { get; set; } = new();
    }

    public class RecordUpdateRequest
    {
        public string TableName { get; set; } = "";
        public string RecordId { get; set; } = "";
        public Dictionary<string, string> Data { get; set; } = new();
    }

    public class ReorderRecordsRequest
    {
        public string TableName { get; set; } = "";
        public List<string> RecordIds { get; set; } = new();
    }

    public class UpdateWidthRequest
    {
        public string TableName { get; set; } = "";
        public string FieldName { get; set; } = "";
        public string Width { get; set; } = "";
    }
}