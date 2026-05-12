using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using KeePass.Plugins;
using KeePassLib;

namespace LDAPass
{
    public sealed class LDAPassExt : Plugin
    {
        private IPluginHost _host;
        private LdapServer _server;
        private ToolStripMenuItem _menuItem;
        private KeePassDb _db;

        public override bool Initialize(IPluginHost host)
        {
            _host = host ?? throw new ArgumentNullException(nameof(host));
            _db = new KeePassDb(GetEntries);
            return true;
        }

        public override ToolStripMenuItem GetMenuItem(PluginMenuType t)
        {
            if (t != PluginMenuType.Main) return null;
            _menuItem = new ToolStripMenuItem
            {
                Text = "Start LDAP Server...",
                ToolTipText = "LDAPass - Expose KeePass entries over LDAP"
            };
            _menuItem.Click += OnMenuClick;
            return _menuItem;
        }

        private void OnMenuClick(object sender, EventArgs e)
        {
            if (_server != null && _server.Running)
            {
                _server.Stop();
                _menuItem.Text = "Start LDAP Server...";
                ShowNotification("LDAPass server stopped");
            }
            else
            {
                var db = _host.Database;
                if (db == null || db.IsOpen == false)
                {
                    MessageBox.Show("Please open a KeePass database first.", "LDAPass",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                int port = 389;
                using (var dialog = new PortInputDialog(port))
                {
                    if (dialog.ShowDialog() != DialogResult.OK)
                        return;
                    port = dialog.Port;
                }

                try
                {
                    _server = new LdapServer(port, _db);
                    _server.Start();
                    _menuItem.Text = "Stop LDAP Server";
                    ShowNotification($"LDAPass server running on port {port}");
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Failed to start server: {ex.Message}", "LDAPass Error",
                        MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        public override void Terminate()
        {
            if (_server != null && _server.Running)
                _server.Stop();
        }

        private void ShowNotification(string text)
        {
            try
            {
                _host.MainWindow.Text = "LDAPass: " + text;
            }
            catch { }
        }

        private List<KeePassEntry> GetEntries()
        {
            var result = new List<KeePassEntry>();
            var db = _host?.Database;
            if (db == null || !db.IsOpen)
                return result;

            TraverseGroup(db.RootGroup, result);
            return result;
        }

        private void TraverseGroup(PwGroup group, List<KeePassEntry> result)
        {
            if (group == null) return;

            foreach (var entry in group.Entries)
            {
                var mapped = MapEntry(entry, group);
                if (mapped != null)
                    result.Add(mapped);
            }

            foreach (var subgroup in group.Groups)
            {
                TraverseGroup(subgroup, result);
            }
        }

        private KeePassEntry MapEntry(PwEntry entry, PwGroup parentGroup)
        {
            if (entry == null) return null;

            var url = ReadSafe(entry, PwDefs.UrlField);
            if (url.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) ||
                url.StartsWith("tel:", StringComparison.OrdinalIgnoreCase))
                return null;

            var result = new KeePassEntry
            {
                Title = ReadSafe(entry, PwDefs.TitleField),
                UserName = ReadSafe(entry, PwDefs.UserNameField),
                Password = ReadSafe(entry, PwDefs.PasswordField),
                Url = url,
                Notes = ReadSafe(entry, PwDefs.NotesField),
                Group = parentGroup?.Name ?? ""
            };

            foreach (var key in entry.Strings.GetKeys())
            {
                if (!IsStandardField(key))
                {
                    result.CustomFields[key] = ReadSafe(entry, key);
                }
            }

            return result;
        }

        private static string ReadSafe(PwEntry entry, string key)
        {
            var ps = entry.Strings.Get(key);
            if (ps == null) return "";
            return ps.ReadString();
        }

        private static bool IsStandardField(string key)
        {
            return key == PwDefs.TitleField
                || key == PwDefs.UserNameField
                || key == PwDefs.PasswordField
                || key == PwDefs.UrlField
                || key == PwDefs.NotesField;
        }
    }

    public class PortInputDialog : Form
    {
        private readonly NumericUpDown _portInput;

        public int Port => (int)_portInput.Value;

        public PortInputDialog(int defaultPort)
        {
            Text = "LDAPass - Port";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MinimizeBox = false;
            MaximizeBox = false;
            ClientSize = new Size(260, 120);
            StartPosition = FormStartPosition.CenterScreen;

            var label = new Label
            {
                Text = "LDAP server port:",
                Location = new Point(12, 15),
                Size = new Size(120, 20)
            };

            _portInput = new NumericUpDown
            {
                Minimum = 1,
                Maximum = 65535,
                Value = defaultPort,
                Location = new Point(140, 13),
                Size = new Size(80, 20)
            };

            var okBtn = new Button
            {
                Text = "OK",
                DialogResult = DialogResult.OK,
                Location = new Point(50, 55),
                Size = new Size(75, 25)
            };

            var cancelBtn = new Button
            {
                Text = "Cancel",
                DialogResult = DialogResult.Cancel,
                Location = new Point(135, 55),
                Size = new Size(75, 25)
            };

            AcceptButton = okBtn;
            CancelButton = cancelBtn;

            Controls.Add(label);
            Controls.Add(_portInput);
            Controls.Add(okBtn);
            Controls.Add(cancelBtn);
        }
    }
}
