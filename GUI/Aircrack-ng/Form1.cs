/*
 *  Aircrack-ng GUI
 *
 *  Copyright (C) 2006,2007  Thomas d'Otreppe
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
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
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

        public Faircrack()
        {
            InitializeComponent();
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
            Console.WriteLine("Windir: {0}", Windir);
            cmd_exe = this.Windir + "\\System32\\cmd.exe";

            this.rbWEP_CheckedChanged(null, null);

            // About box
            this.lblAboutText.Text = "Aircrack-ng GUI v" + Assembly.GetCallingAssembly().GetName().Version.ToString();
            this.lblAboutText.Left = (this.tAboutBox.Width - this.lblAboutText.Width) / 2;

            this.lblChangelog.Text =
                  "v1.0.0.1\n"
                + "    - Added About box\n"
                + "    - Modified Aircrack-ng tab\n"
                + "\n"
                + "v1.0\n"
                + "    First version\n";

            this.lblCopyright.Text =
                "Copyright © 2006, 2007 Thomas d'Otreppe";

            this.lblCopyright.Left = (this.tAboutBox.Width - this.lblCopyright.Width) / 2;
            //End about box

            Application.DoEvents();
        }

        /// <summary>
        /// Standard Open file dialog
        /// </summary>
        /// <param name="Filter"></param>
        /// <param name="FilterIndex"></param>
        /// <param name="multipleFiles"></param>
        /// <returns></returns>
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

        /// <summary>
        /// Open a file dialog to select capture files
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void btOpenCapFiles_Click(object sender, EventArgs e)
        {
            string captureFileExtensions =
                "Capture files (*.cap, *.ivs, *.dump)|*.cap;*.ivs;*.dump|All files (*.*)|*.*";
            this.tbFilenames.Text += " " + this.FileDialog(captureFileExtensions, 0, true).Trim();
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

            if (this.rbWEP.Checked)
            {
                // Force WEP Mode
                options += " -a 1";

                //Key size
                options += " -n " + this.cbKeySize.Text;

                // Force showing ascii
                options += " -s";
            }
            else
            {
                // Force WPA Mode
                options += " -a 2";
            }
            

            // Do we have to use a dictionnary?
            if (this.rbWPA.Checked || (this.rbWEP.Checked && this.cbUseWordlist.Checked))
            {
                if (checkFileExist(this.tbWPADico.Text,
                        "Please specify a wordlist and/or\n"
                        + "check that dictionnary file exist") == false)
                {
                    return;
                }
                options += "-w \"" + this.tbWPADico.Text + "\"";
            }

            // Advanced options
            if (this.cbAdvancedOptions.Checked)
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
            
            Console.WriteLine("Launch command: {0}", launch);

                // " " + type + " file does not exist",
            if (checkFileExist(path, "Aircrack-ng executable"))
            {
                try
                {
                    Process.Start(cmd_exe, "/k \" " + launch + " \"");
                }
                catch
                {
                    MessageBox.Show("Failed to start Aircrack-ng", this.Text);
                }
            }
        }

        private bool checkFileExist(string path, string message)
        {
            bool ret = false;
            if (string.IsNullOrEmpty(path) == false)
                ret = File.Exists(path);

            if (ret == false)
            {
                string completeMsg = "Failed to start Aircrack-ng.";
                if (string.IsNullOrEmpty(message) == false)
                    completeMsg += "\n" + message;

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
            this.tbWPADico.Text =
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

        private void rbWEP_CheckedChanged(object sender, EventArgs e)
        {
            this.pWEPstdOption.Visible = this.rbWEP.Checked && !this.cbUseWordlist.Checked;
            if (this.rbWEP.Checked)
            {
                this.pWordlist.Visible = this.cbUseWordlist.Checked;
            }
            else
            {
                this.pWordlist.Visible = true;
            }

            this.pWEPKeySize.Visible = this.rbWEP.Checked;
            this.cbUseWordlist.Visible = this.rbWEP.Checked;
        }

        private void cbUseWordlist_CheckedChanged(object sender, EventArgs e)
        {
            this.pWordlist.Visible = this.cbUseWordlist.Checked;
            this.pWEPstdOption.Visible = !this.cbUseWordlist.Checked;
        }

    }
}