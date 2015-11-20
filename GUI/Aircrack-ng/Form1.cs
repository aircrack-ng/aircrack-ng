/*
 *  Aircrack-ng GUI
 *
 *  Copyright (C) 2006-2008, 2015  Thomas d'Otreppe
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

using System;
using System.Windows.Forms;
using System.Diagnostics;
using System.IO;
using System.Reflection;


namespace Aircrack_ng
{
    public partial class Faircrack : Form
    {
        private string currentDir;
        private int nbCpu;
        private string Windir;
        private string cmd_exe;
        private string lastDirectory = ".";


        private const String debugFile = "debug.log";
        private StreamWriter debugStream = null;

        private string Changelog =
                  "v1.0.0.7\n"
                + "    - Updated project to VS 2015 and .NET 3.5\n"
                + "\n"
                + "v1.0.0.6\n"
                + "    - Fixed \"Choose\" button (airdecap-ng)\n"
                + "\n"
                + "v1.0.0.5\n"
                + "    - Allow choosing WEP key size when using PTW\n"
                + "\n"
                + "v1.0.0.4\n"
                + "    - Fixed cracking with a wordlist\n"
                + "\n"
                + "v1.0.0.3\n"
                + "    - Added logging to debug.log\n"
                + "    - Added PTW option\n"
                + "\n"
                + "v1.0.0.2\n"
                + "    - Fixed wordlist selection\n"
                + "\n"
                + "v1.0.0.1\n"
                + "    - Added About box\n"
                + "    - Modified Aircrack-ng tab\n"
                + "\n"
                + "v1.0\n"
                + "    - First version\n";

        public Faircrack()
        {
            InitializeComponent();

            // Initialize logging
            this.initLog();

            this.ShowHideEssidBssid(this.cbBssid, null);
            this.ShowHideEssidBssid(this.cbEssid, null);

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
            // Log windows directory
            this.writeLog("Windir: " + Windir);

            cmd_exe = this.Windir + "\\System32\\cmd.exe";
            // End windows directory

            this.rbWEP_CheckedChanged(null, null);

            // About box
            this.lblAboutText.Text = "Aircrack-ng GUI v" + Assembly.GetCallingAssembly().GetName().Version.ToString();
            this.lblAboutText.Left = (this.tAboutBox.Width - this.lblAboutText.Width) / 2;

            // Log version
            this.writeLog(this.lblAboutText.Text);

            // Add changelog
            this.rtbChangelog.Text = this.Changelog;

            // ... and copyright
            FileVersionInfo versionInfo = FileVersionInfo.GetVersionInfo(Assembly.GetEntryAssembly().Location);
            
            this.lblCopyright.Text = versionInfo.LegalCopyright;

            this.lblCopyright.Left = (this.tAboutBox.Width - this.lblCopyright.Width) / 2;
            //End about box

            Application.DoEvents();
        }

        /// <summary>
        /// Initialize logging
        /// </summary>
        private void initLog()
        {
            // Make sure it doesn't crash
            try
            {
                debugStream = new StreamWriter(debugFile, true);
                this.writeLog("Application starting");
            }
            catch { }

        }

        /// <summary>
        /// Write to log file
        /// </summary>
        /// <param name="text"></param>
        private void writeLog(string text)
        {
            // Make sure it doesn't crash
            try
            {
                this.debugStream.WriteLine("{0} - {1}", DateTime.Now.ToString(), text);
                this.debugStream.Flush();
            }
            catch { }
        }

        /// <summary>
        /// Standard Open file dialog
        /// </summary>
        /// <param name="Filter"></param>
        /// <param name="FilterIndex"></param>
        /// <param name="multipleFiles"></param>
        /// <param name="separator"></param>
        /// <returns></returns>
        private string FileDialog(string Filter, int FilterIndex, bool multipleFiles, string separator)
        {
          return FileDialog(Filter, FilterIndex, multipleFiles, separator, ".");
        }
        /// <summary>
        /// Standard Open file dialog
        /// </summary>
        /// <param name="Filter"></param>
        /// <param name="FilterIndex"></param>
        /// <param name="multipleFiles"></param>
        /// <param name="separator"></param>
        /// <param name="initDirectory"></param>
        /// <returns></returns>
        private string FileDialog(string Filter, int FilterIndex, bool multipleFiles, string separator, string initDirectory)
        {
            string fileseparator = separator;
            string filenames = "";
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Filter = Filter;
            ofd.FilterIndex = FilterIndex;
            ofd.InitialDirectory = initDirectory;
            ofd.Multiselect = multipleFiles;
            ofd.RestoreDirectory = true;
            ofd.DereferenceLinks = true;
            ofd.CheckPathExists = true;
            ofd.CheckFileExists = true;

            if (string.IsNullOrEmpty(fileseparator))
                fileseparator = " ";

            if (ofd.ShowDialog() == DialogResult.OK)
            {
                foreach (string filename in ofd.FileNames)
                {
                    filenames += fileseparator;
                    
                    if (filename.Contains(" "))
                        filenames += "\"" + filename + "\"";
                    else
                        filenames += filename;    
                }

                // Save last directory
                if (ofd.FileNames.Length > 0)
                {
                    this.lastDirectory = System.IO.Path.GetDirectoryName(ofd.FileNames[ofd.FileNames.Length - 1]);
                }
            }
            return filenames;
        }

        /// <summary>
        /// Open a file dialog to select capture files
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btOpenCapFiles_Click(object sender, EventArgs e)
        {
            string captureFileExtensions =
                "Capture files (*.cap, *.pcap, *.ivs, *.dump)|*.cap;*.pcap;*.ivs;*.dump|All files (*.*)|*.*";
            string resultFilename = this.FileDialog(captureFileExtensions, 0, true, null, this.lastDirectory);
                //System.IO.Path.GetFullPath
            this.tbFilenames.Text += " " + resultFilename.Trim();
            this.tbFilenames.Text = this.tbFilenames.Text.Trim();
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

        /// <summary>
        /// Called when clicking on Laucnh WZCook
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
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
                this.cbAdvancedOptions.Checked && !this.cbPTW.Checked;
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

            if (this.rbWEP.Checked)
            {
                // Force WEP Mode
                options += " -a 1";

                if (this.cbPTW.Checked)
                {
                    // use PTW
                    options += " -z";
                }
                else
                {
                    //Key size
                    options += " -n " + this.cbKeySize.Text;

                    // Force showing ascii
                    options += " -s";
                }
            }
            else
            {
                // Force WPA Mode
                options += " -a 2";
            }
            

            // Do we have to use a dictionary?
            if (this.rbWPA.Checked || (this.rbWEP.Checked && this.cbUseWordlist.Checked && !this.cbPTW.Checked))
            {
                if (checkFileExist(this.tbWPADico.Text,
                        "Please specify a wordlist and/or\n"
                        + "check that dictionary file exist") == false)
                {
                    return;
                }
                options += " -w \"" + this.tbWPADico.Text + "\"";
            }

            // Advanced options
            if (this.cbAdvancedOptions.Checked && !this.cbPTW.Checked)
            {

                // BSSID
                if (this.cbBssid.Checked && !string.IsNullOrEmpty(this.tbBssid.Text))
                {
                    if (this.tbBssid.Text.Contains(" "))
                    {
                        MessageBox.Show("Invalid BSSID", this.Text);
                        return;
                    }
                    options += " -b " + this.tbBssid.Text;
                }

                // ESSID?
                if (this.cbEssid.Checked && !string.IsNullOrEmpty(this.tbBssid.Text))
                    options += " -e \"" + this.tbEssid.Text + "\"";

                if (this.rbWEP.Checked && !this.cbUseWordlist.Checked)
                {
                    //Limit search to Alphanumeric values
                    if (this.cbAlphanum.Checked)
                        options += " -c";

                    //Limit search to BCD characters
                    if (this.cbBCD.Checked)
                        options += " -t";

                    //Limit search to Numeric Values (Fritz!BOX)
                    if (this.cbFritzbox.Checked)
                        options += " -h";

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
            }

            options = options.Trim();
            // End options

            path = this.currentDir + "\\aircrack-ng.exe";
            launch = "\"" + path + "\" " + options + " " + this.tbFilenames.Text;
            
            this.writeLog("Launch command: " + launch);

                // " " + type + " file does not exist",
            if (checkFileExist(path, "Aircrack-ng executable"))
            {
                try
                {
                    Process.Start(cmd_exe, "/k \" " + launch + " \"");
                }
                catch
                {
                    this.writeLog("Failed to start Aircrack-ng process");
                    MessageBox.Show("Failed to start Aircrack-ng", this.Text);
                }
            }
        }

        /// <summary>
        /// Checking if a file exist
        /// </summary>
        /// <param name="path">Path to the file</param>
        /// <param name="message">Message to show</param>
        /// <returns></returns>
        private bool checkFileExist(string path, string message)
        {
            bool ret = false;

            // Checking if file exist
            if (string.IsNullOrEmpty(path) == false)
                ret = File.Exists(path);

            if (ret == false)
            {
                string completeMsg = "Failed to start Aircrack-ng.";
                if (string.IsNullOrEmpty(message) == false)
                    completeMsg += "\n" + message;

                // Write it to log file
                this.writeLog("File <" + path + "> does not exist");

                MessageBox.Show(completeMsg, this.Text);
            }
            return ret;
        }

        private void btLaunchAirodump_Click(object sender, EventArgs e)
        {
            try
            {
                Process.Start("airodump-ng.exe");
            }
            catch
            {
                this.writeLog("Failed to start Airodump-ng");
                MessageBox.Show("Failed to start Airodump-ng", this.Text);
            }
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
            this.tbWPADico.Text += this.FileDialog("Wordlist|*.*", 0, true, ",").Trim();

            this.tbWPADico.Text = this.tbWPADico.Text.Trim(',').Trim('\"');
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
                // No capture file given
                this.writeLog("Aircrack-ng - Missing capture file(s) to crack");
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

            this.writeLog("Launch command: " + launch);

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
                "Capture files (*.cap, *.pcap, *.dump)|*.cap;*.pcap;*.dump|All files (*.*)|*.*";

            this.tbDecapFile.Text = this.FileDialog(captureFileExtensions, 0, false, null).Trim();
        }

        private void rbWEP_CheckedChanged(object sender, EventArgs e)
        {
            this.pWEPstdOption.Visible = this.rbWEP.Checked && !this.cbUseWordlist.Checked && !this.cbPTW.Checked;
            if (this.rbWEP.Checked)
            {
                this.cbPTW.Visible = true;
                this.pWordlist.Visible = this.cbUseWordlist.Checked && !this.cbPTW.Checked;
            }
            else
            {
                this.cbPTW.Visible = false;
                this.pWordlist.Visible = true;
            }

            this.pWEPKeySize.Visible = this.rbWEP.Checked;
            this.cbUseWordlist.Visible = this.rbWEP.Checked && !this.cbPTW.Checked;
        }

        private void cbUseWordlist_CheckedChanged(object sender, EventArgs e)
        {
            this.pWordlist.Visible = this.cbUseWordlist.Checked;
            this.pWEPstdOption.Visible = !this.cbUseWordlist.Checked;
            this.cbPTW.Enabled = !this.cbUseWordlist.Checked;
        }

        private void cbPTW_CheckedChanged(object sender, EventArgs e)
        {
            this.cbUseWordlist.Enabled = !this.cbPTW.Checked;
            this.cbAdvancedOptions.Enabled = !this.cbPTW.Checked;
            this.pAdvancedOptions.Visible = !this.cbPTW.Checked;
            this.cbUseWordlist_CheckedChanged(null, null);
            this.rbWEP_CheckedChanged(null, null);
            this.cbAdvancedOptions_CheckedChanged(null, null);

        }

        private void Faircrack_FormClosing(object sender, FormClosingEventArgs e)
        {
            this.writeLog("Application closing");
            this.debugStream.Close();
        }

    }
}