using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.Diagnostics;
using System.IO;


namespace Aircrack_ng
{
    public partial class Faircrack : Form
    {
        private bool WEPAircrack;
        private string currentDir;
        private int nbCpu;
        private string Windir;
        private string cmd_exe;

        public Faircrack()
        {
            InitializeComponent();
            this.ShowHideEssidBssid(this.cbBssid, null);
            this.ShowHideEssidBssid(this.cbEssid, null);
            this.WEPAircrack = true;

            try
            {
                string NbrCpu = Environment.GetEnvironmentVariable("NUMBER_OF_PROCESSORS");
                this.nbCpu = int.Parse(NbrCpu);
                this.cbMultiThreading.Visible = this.nbCpu > 1;
            }
            catch
            {
                this.nbCpu = 1;
            }
            this.cbAdvancedOptions_CheckedChanged(null, null);
            this.currentDir = Directory.GetCurrentDirectory();
            this.clbKorek.CheckOnClick = true;
            this.cbPMKDecap_CheckedChanged(null, null);
            this.ShowHideEssidBssidDecap(this.cbBssidDecap, null);
            this.ShowHideEssidBssidDecap(this.cbEssidDecap, null);
            this.rbWepDecap_CheckedChanged(null, null);

            //Get Windows directory
            try
            {
                this.Windir = Environment.GetEnvironmentVariable("SystemRoot");
            }
            catch
            {
                try
                {
                    this.Windir = Environment.GetEnvironmentVariable("windir");
                }
                catch
                {
                    this.Windir = @"C:\Windows";
                }
            }
            Console.WriteLine("Windir: {0}", Windir);
            cmd_exe = this.Windir + "\\System32\\cmd.exe";
        }

        private string FileDialog(string Filter, int FilterIndex, bool multipleFiles)
        {
            string filenames = "";
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Filter = Filter;
            ofd.FilterIndex = FilterIndex;
            ofd.InitialDirectory = ".";
            ofd.Multiselect = multipleFiles;
            ofd.RestoreDirectory = true;
            ofd.DereferenceLinks = true;
            ofd.CheckPathExists = true;
            ofd.CheckFileExists = true;
            if (ofd.ShowDialog() == DialogResult.OK)
            {
                foreach (string filename in ofd.FileNames)
                {
                    filenames += " ";
                    if (filename.Contains(" "))
                        filenames += "\"" + filename + "\"";
                    else
                        filenames += filename;
                }
            }
            return filenames;
        }

        private void btOpenCapFiles_Click(object sender, EventArgs e)
        {
            string captureFileExtensions =
                "Capture files (*.cap, *.ivs, *.dump)|*.cap;*.ivs;*.dump|All files (*.*)|*.*";
            this.tbFilenames.Text += " " + this.FileDialog(captureFileExtensions, 0, true).Trim();
        }

        private void tabWepWpa_SelectedIndexChanged(object sender, EventArgs e)
        {
            this.WEPAircrack = !this.WEPAircrack;
        }

        private void ShowHideEssidBssid(object sender, EventArgs e)
        {
            if ((CheckBox)sender == this.cbBssid)
            {
                this.tbBssid.Visible = this.cbBssid.Checked;
            }
            else
            {
                this.tbEssid.Visible = this.cbEssid.Checked;
            }
        }

        private void btLaunchWzcook_Click(object sender, EventArgs e)
        {
            try
            {
                Process.Start(this.currentDir + @"\wzcook.exe");
            }
            catch
            {
                MessageBox.Show("Failed to start WZCook", this.Text);
            }
        }

        private void cbAdvancedOptions_CheckedChanged(object sender, EventArgs e)
        {
            this.pAdvancedOptions.Visible =
                this.cbAdvancedOptions.Checked;
        }

        private string setOptions(bool isChecked, string option, string arg)
        {
            return string.Empty;
                
        }

        private void btLaunchCrack_Click(object sender, EventArgs e)
        {
            string launch, options, path;

            options = string.Empty;

            if (string.IsNullOrEmpty(this.tbFilenames.Text))
            {
                MessageBox.Show("Give at least one capture file to crack", this.Text);
                return;
            }
            // Setting options

            if (this.cbAdvancedOptions.Checked)
            {

                if (this.cbForceAttack.Checked)
                {
                    if (this.WEPAircrack)
                        options += " -a 1";
                    else
                        options += " -a 2";
                }

                if (this.cbBssid.Checked && !string.IsNullOrEmpty(this.tbBssid.Text))
                {
                    if (this.tbBssid.Text.Contains(" "))
                    {
                        MessageBox.Show("Invalid BSSID", this.Text);
                        return;
                    }
                    options += " -b " + this.tbBssid.Text;
                }

                if (this.cbEssid.Checked && !string.IsNullOrEmpty(this.tbBssid.Text))
                    options += " -e " + this.tbEssid.Text;

                if (this.WEPAircrack)
                {
                    options += " -s";

                    //Limit search to Alphanumeric values
                    if (this.cbAlphanum.Checked)
                        options += " -c";

                    //Limit search to BCD characters
                    if (this.cbBCD.Checked)
                        options += " -t";

                    //Limit search to Numeric Values (Fritz!BOX)
                    if (this.cbFritzbox.Checked)
                        options += " -h";

                    //Key size
                    options += " -n " + this.cbKeySize.Text;

                    //Disabling KoreK attacks
                    foreach (String elem in this.clbKorek.CheckedItems)
                    {
                        options += " -k " + int.Parse(elem);
                    }

                    //Fudge factor
                    options += " -f " + this.NUDFudge.Value.ToString();

                    if (this.cbSingleBrute.Checked)
                    {
                        options += " -y";
                    }
                    else
                    {
                        options += " -x" + this.NUDkbBrute.Value.ToString();
                        if (this.cbMultiThreading.Checked == false)
                            options += " -X";
                    }

                }
                else
                {
                    if (string.IsNullOrEmpty(this.tbWPADico.Text))
                    {
                        MessageBox.Show("Please specify a wordlist", this.Text);
                        return;
                    }
                    options += "-w " + this.tbWPADico.Text;
                }
                options = options.Trim();
            }

            // End setting options


            path = this.currentDir + "\\aircrack-ng.exe";
            launch = "\"" + path + "\" " + options + " " + this.tbFilenames.Text;
            
            Console.WriteLine("Launch command: {0}", launch);

            try
            {
                if (!File.Exists(path))
                    throw (new Exception());
                Process.Start(cmd_exe, "/k \" " + launch + " \"");
            }
            catch
            {
                MessageBox.Show("Failed to start Aircrack-ng", this.Text);
            }
        }

        private void btLaunchAirodump_Click(object sender, EventArgs e)
        {
            try
            {
                Process.Start("airodump-ng.exe");
            }
            catch
            {
                MessageBox.Show("Failed to start Airodump-ng", this.Text);
            }
        }

        private void tbFilenames_DragDrop(object sender, DragEventArgs e)
        {
            //Console.WriteLine("DragEventArgs: {0} - sender: {1}", e.ToString(), sender.ToString());
            //Console.WriteLine("DragEventAgrs.Data.GetData(): {0}", e.Data.GetData("String").ToString());
        }

        private void cbSingleBrute_CheckedChanged(object sender, EventArgs e)
        {
            bool enable = !this.cbSingleBrute.Checked;
            this.NUDkbBrute.Enabled = enable;
            this.cbMultiThreading.Enabled = enable;
            this.lkbBrute.Enabled = enable;
        }

        private void btOpenDico_Click(object sender, EventArgs e)
        {
            this.tbWPADico.Text += " " +
                this.FileDialog("Wordlist|*.*", 0, true).Trim();
        }

        private void cbPMKDecap_CheckedChanged(object sender, EventArgs e)
        {
            this.tbPMKDecap.Visible = this.cbPMKDecap.Checked;
        }

        private void ShowHideEssidBssidDecap(object sender, EventArgs e)
        {
            if ((CheckBox)sender == this.cbBssidDecap)
            {
                this.tbBssidDecap.Visible = this.cbBssidDecap.Checked;
            }
            else
            {
                this.tbEssidDecap.Visible = this.cbEssidDecap.Checked;
            }
        }

        private void btLaunchAirdecap_Click(object sender, EventArgs e)
        {
            string path, options, launch, keypass;

            if (string.IsNullOrEmpty(this.tbDecapFile.Text))
            {
                MessageBox.Show("Give at least one capture file to crack", this.Text);
                return;
            }

            options = string.Empty;

            //Setting options

            if (this.cbNotRemove80211.Checked)
                options += " -l";

            if (this.cbEssidDecap.Checked && 
                !string.IsNullOrEmpty(this.tbEssidDecap.Text))
                options += " -e " + this.tbEssidDecap.Text;

            if (this.cbBssidDecap.Checked && 
                !string.IsNullOrEmpty(this.tbBssidDecap.Text))
                options += " -b " + this.tbBssidDecap.Text;

            keypass = this.tbKeyPassphrase.Text;

            if (this.rbWepDecap.Checked)
            {
                options += "-w " + keypass;
            }
            else
            {
                options += "-p " + keypass;

                if (this.cbPMKDecap.Checked)
                    options += "-k " + this.tbPMKDecap.Text;
            }



            //End Setting options

            path = this.currentDir + "\\airdecap-ng.exe";
            launch = "\"" + path + "\" " + options.Trim() + " " + this.tbFilenames.Text;

            Console.WriteLine("Launch command: {0}", launch);

            try
            {
                if (!File.Exists(path))
                    throw (new Exception());
                Process.Start(cmd_exe, "/k \" " + launch + " \"");
            }
            catch
            {
                MessageBox.Show("Failed to start Airdecap-ng", this.Text);
            }
        }

        private void rbWepDecap_CheckedChanged(object sender, EventArgs e)
        {
            this.lEncryptionText.Text = "Key (hex)";
            this.cbPMKDecap.Visible = false;
            this.tbPMKDecap.Visible = false;
        }

        private void rbWPADecap_CheckedChanged(object sender, EventArgs e)
        {
            this.lEncryptionText.Text = "Passphrase";
            this.cbPMKDecap.Visible = true;
            this.tbPMKDecap.Visible = true;
        }

        private void btLoadDecapFile_Click(object sender, EventArgs e)
        {
            string captureFileExtensions =
                "Capture files (*.cap, *.dump)|*.cap;*.dump|All files (*.*)|*.*";
            this.tbFilenames.Text = " " + this.FileDialog(captureFileExtensions, 0, false).Trim();

        }

    }
}