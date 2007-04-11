namespace Aircrack_ng
{
    partial class Faircrack
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.cbAdvancedOptions = new System.Windows.Forms.CheckBox();
            this.pAdvancedOptions = new System.Windows.Forms.Panel();
            this.cbEssid = new System.Windows.Forms.CheckBox();
            this.tabWepWpa = new System.Windows.Forms.TabControl();
            this.tabWep = new System.Windows.Forms.TabPage();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.cbSingleBrute = new System.Windows.Forms.CheckBox();
            this.cbMultiThreading = new System.Windows.Forms.CheckBox();
            this.lkbBrute = new System.Windows.Forms.Label();
            this.NUDkbBrute = new System.Windows.Forms.NumericUpDown();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.cbFritzbox = new System.Windows.Forms.CheckBox();
            this.cbBCD = new System.Windows.Forms.CheckBox();
            this.cbAlphanum = new System.Windows.Forms.CheckBox();
            this.label5 = new System.Windows.Forms.Label();
            this.clbKorek = new System.Windows.Forms.CheckedListBox();
            this.label4 = new System.Windows.Forms.Label();
            this.NUDFudge = new System.Windows.Forms.NumericUpDown();
            this.cbKeySize = new System.Windows.Forms.ComboBox();
            this.label3 = new System.Windows.Forms.Label();
            this.label2 = new System.Windows.Forms.Label();
            this.tabWpa = new System.Windows.Forms.TabPage();
            this.label6 = new System.Windows.Forms.Label();
            this.btOpenDico = new System.Windows.Forms.Button();
            this.tbWPADico = new System.Windows.Forms.TextBox();
            this.cbForceAttack = new System.Windows.Forms.CheckBox();
            this.cbBssid = new System.Windows.Forms.CheckBox();
            this.tbBssid = new System.Windows.Forms.TextBox();
            this.tbEssid = new System.Windows.Forms.TextBox();
            this.btOpenCapFiles = new System.Windows.Forms.Button();
            this.label1 = new System.Windows.Forms.Label();
            this.btLaunchCrack = new System.Windows.Forms.Button();
            this.tbFilenames = new System.Windows.Forms.TextBox();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.btLaunchAirodump = new System.Windows.Forms.Button();
            this.tabPage3 = new System.Windows.Forms.TabPage();
            this.lEncryptionText = new System.Windows.Forms.Label();
            this.tbKeyPassphrase = new System.Windows.Forms.TextBox();
            this.tbPMKDecap = new System.Windows.Forms.TextBox();
            this.label10 = new System.Windows.Forms.Label();
            this.cbPMKDecap = new System.Windows.Forms.CheckBox();
            this.rbWPADecap = new System.Windows.Forms.RadioButton();
            this.rbWepDecap = new System.Windows.Forms.RadioButton();
            this.cbBssidDecap = new System.Windows.Forms.CheckBox();
            this.cbEssidDecap = new System.Windows.Forms.CheckBox();
            this.tbEssidDecap = new System.Windows.Forms.TextBox();
            this.btLaunchAirdecap = new System.Windows.Forms.Button();
            this.tbBssidDecap = new System.Windows.Forms.TextBox();
            this.cbNotRemove80211 = new System.Windows.Forms.CheckBox();
            this.btLoadDecapFile = new System.Windows.Forms.Button();
            this.tbDecapFile = new System.Windows.Forms.TextBox();
            this.label7 = new System.Windows.Forms.Label();
            this.tabPage4 = new System.Windows.Forms.TabPage();
            this.btLaunchWzcook = new System.Windows.Forms.Button();
            this.tabControl1.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.pAdvancedOptions.SuspendLayout();
            this.tabWepWpa.SuspendLayout();
            this.tabWep.SuspendLayout();
            this.groupBox2.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.NUDkbBrute)).BeginInit();
            this.groupBox1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.NUDFudge)).BeginInit();
            this.tabWpa.SuspendLayout();
            this.tabPage2.SuspendLayout();
            this.tabPage3.SuspendLayout();
            this.tabPage4.SuspendLayout();
            this.SuspendLayout();
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.tabPage1);
            this.tabControl1.Controls.Add(this.tabPage2);
            this.tabControl1.Controls.Add(this.tabPage3);
            this.tabControl1.Controls.Add(this.tabPage4);
            this.tabControl1.Location = new System.Drawing.Point(6, 9);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(605, 462);
            this.tabControl1.TabIndex = 0;
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.cbAdvancedOptions);
            this.tabPage1.Controls.Add(this.pAdvancedOptions);
            this.tabPage1.Controls.Add(this.btOpenCapFiles);
            this.tabPage1.Controls.Add(this.label1);
            this.tabPage1.Controls.Add(this.btLaunchCrack);
            this.tabPage1.Controls.Add(this.tbFilenames);
            this.tabPage1.Location = new System.Drawing.Point(4, 22);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage1.Size = new System.Drawing.Size(597, 436);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "Aircrack-ng";
            this.tabPage1.UseVisualStyleBackColor = true;
            // 
            // cbAdvancedOptions
            // 
            this.cbAdvancedOptions.AutoSize = true;
            this.cbAdvancedOptions.Location = new System.Drawing.Point(9, 32);
            this.cbAdvancedOptions.Name = "cbAdvancedOptions";
            this.cbAdvancedOptions.Size = new System.Drawing.Size(201, 17);
            this.cbAdvancedOptions.TabIndex = 11;
            this.cbAdvancedOptions.Text = "Use WPA or advanced WEP options";
            this.cbAdvancedOptions.UseVisualStyleBackColor = true;
            this.cbAdvancedOptions.CheckedChanged += new System.EventHandler(this.cbAdvancedOptions_CheckedChanged);
            // 
            // pAdvancedOptions
            // 
            this.pAdvancedOptions.Controls.Add(this.cbEssid);
            this.pAdvancedOptions.Controls.Add(this.tabWepWpa);
            this.pAdvancedOptions.Controls.Add(this.cbForceAttack);
            this.pAdvancedOptions.Controls.Add(this.cbBssid);
            this.pAdvancedOptions.Controls.Add(this.tbBssid);
            this.pAdvancedOptions.Controls.Add(this.tbEssid);
            this.pAdvancedOptions.Location = new System.Drawing.Point(6, 55);
            this.pAdvancedOptions.Name = "pAdvancedOptions";
            this.pAdvancedOptions.Size = new System.Drawing.Size(588, 349);
            this.pAdvancedOptions.TabIndex = 10;
            // 
            // cbEssid
            // 
            this.cbEssid.AutoSize = true;
            this.cbEssid.Location = new System.Drawing.Point(3, 3);
            this.cbEssid.Name = "cbEssid";
            this.cbEssid.Size = new System.Drawing.Size(96, 17);
            this.cbEssid.TabIndex = 5;
            this.cbEssid.Text = "Specify ESSID";
            this.cbEssid.UseVisualStyleBackColor = true;
            this.cbEssid.CheckedChanged += new System.EventHandler(this.ShowHideEssidBssid);
            // 
            // tabWepWpa
            // 
            this.tabWepWpa.Controls.Add(this.tabWep);
            this.tabWepWpa.Controls.Add(this.tabWpa);
            this.tabWepWpa.Location = new System.Drawing.Point(3, 75);
            this.tabWepWpa.Name = "tabWepWpa";
            this.tabWepWpa.SelectedIndex = 0;
            this.tabWepWpa.Size = new System.Drawing.Size(582, 269);
            this.tabWepWpa.TabIndex = 4;
            this.tabWepWpa.SelectedIndexChanged += new System.EventHandler(this.tabWepWpa_SelectedIndexChanged);
            // 
            // tabWep
            // 
            this.tabWep.Controls.Add(this.groupBox2);
            this.tabWep.Controls.Add(this.groupBox1);
            this.tabWep.Controls.Add(this.label5);
            this.tabWep.Controls.Add(this.clbKorek);
            this.tabWep.Controls.Add(this.label4);
            this.tabWep.Controls.Add(this.NUDFudge);
            this.tabWep.Controls.Add(this.cbKeySize);
            this.tabWep.Controls.Add(this.label3);
            this.tabWep.Controls.Add(this.label2);
            this.tabWep.Location = new System.Drawing.Point(4, 22);
            this.tabWep.Name = "tabWep";
            this.tabWep.Padding = new System.Windows.Forms.Padding(3);
            this.tabWep.Size = new System.Drawing.Size(574, 243);
            this.tabWep.TabIndex = 0;
            this.tabWep.Text = "WEP";
            this.tabWep.UseVisualStyleBackColor = true;
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.cbSingleBrute);
            this.groupBox2.Controls.Add(this.cbMultiThreading);
            this.groupBox2.Controls.Add(this.lkbBrute);
            this.groupBox2.Controls.Add(this.NUDkbBrute);
            this.groupBox2.Location = new System.Drawing.Point(290, 120);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(181, 107);
            this.groupBox2.TabIndex = 8;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Bruteforce";
            // 
            // cbSingleBrute
            // 
            this.cbSingleBrute.AutoSize = true;
            this.cbSingleBrute.Location = new System.Drawing.Point(16, 77);
            this.cbSingleBrute.Name = "cbSingleBrute";
            this.cbSingleBrute.Size = new System.Drawing.Size(140, 17);
            this.cbSingleBrute.TabIndex = 3;
            this.cbSingleBrute.Text = "Single Bruteforce attack";
            this.cbSingleBrute.UseVisualStyleBackColor = true;
            this.cbSingleBrute.CheckedChanged += new System.EventHandler(this.cbSingleBrute_CheckedChanged);
            // 
            // cbMultiThreading
            // 
            this.cbMultiThreading.AutoSize = true;
            this.cbMultiThreading.Checked = true;
            this.cbMultiThreading.CheckState = System.Windows.Forms.CheckState.Checked;
            this.cbMultiThreading.Location = new System.Drawing.Point(16, 54);
            this.cbMultiThreading.Name = "cbMultiThreading";
            this.cbMultiThreading.Size = new System.Drawing.Size(143, 17);
            this.cbMultiThreading.TabIndex = 2;
            this.cbMultiThreading.Text = "Multithreading bruteforce";
            this.cbMultiThreading.UseVisualStyleBackColor = true;
            // 
            // lkbBrute
            // 
            this.lkbBrute.AutoSize = true;
            this.lkbBrute.Location = new System.Drawing.Point(13, 16);
            this.lkbBrute.Name = "lkbBrute";
            this.lkbBrute.Size = new System.Drawing.Size(72, 26);
            this.lkbBrute.TabIndex = 1;
            this.lkbBrute.Text = "Last keybytes\r\nbruteforce";
            // 
            // NUDkbBrute
            // 
            this.NUDkbBrute.Location = new System.Drawing.Point(102, 19);
            this.NUDkbBrute.Maximum = new decimal(new int[] {
            2,
            0,
            0,
            0});
            this.NUDkbBrute.Name = "NUDkbBrute";
            this.NUDkbBrute.Size = new System.Drawing.Size(48, 20);
            this.NUDkbBrute.TabIndex = 0;
            this.NUDkbBrute.Value = new decimal(new int[] {
            1,
            0,
            0,
            0});
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.cbFritzbox);
            this.groupBox1.Controls.Add(this.cbBCD);
            this.groupBox1.Controls.Add(this.cbAlphanum);
            this.groupBox1.Location = new System.Drawing.Point(290, 6);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(181, 97);
            this.groupBox1.TabIndex = 7;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Key search filter";
            // 
            // cbFritzbox
            // 
            this.cbFritzbox.AutoSize = true;
            this.cbFritzbox.Location = new System.Drawing.Point(16, 65);
            this.cbFritzbox.Name = "cbFritzbox";
            this.cbFritzbox.Size = new System.Drawing.Size(118, 17);
            this.cbFritzbox.TabIndex = 2;
            this.cbFritzbox.Text = "Numeric (Fritz!BOX)";
            this.cbFritzbox.UseVisualStyleBackColor = true;
            // 
            // cbBCD
            // 
            this.cbBCD.AutoSize = true;
            this.cbBCD.Location = new System.Drawing.Point(16, 42);
            this.cbBCD.Name = "cbBCD";
            this.cbBCD.Size = new System.Drawing.Size(101, 17);
            this.cbBCD.TabIndex = 1;
            this.cbBCD.Text = "BCD characters";
            this.cbBCD.UseVisualStyleBackColor = true;
            // 
            // cbAlphanum
            // 
            this.cbAlphanum.AutoSize = true;
            this.cbAlphanum.Location = new System.Drawing.Point(16, 19);
            this.cbAlphanum.Name = "cbAlphanum";
            this.cbAlphanum.Size = new System.Drawing.Size(143, 17);
            this.cbAlphanum.TabIndex = 0;
            this.cbAlphanum.Text = "Alphanumeric characters";
            this.cbAlphanum.UseVisualStyleBackColor = true;
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(13, 73);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(74, 26);
            this.label5.TabIndex = 6;
            this.label5.Text = "Disable KoreK\r\nattacks";
            // 
            // clbKorek
            // 
            this.clbKorek.FormattingEnabled = true;
            this.clbKorek.Items.AddRange(new object[] {
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "10",
            "11",
            "12",
            "13",
            "14",
            "15",
            "16",
            "17"});
            this.clbKorek.Location = new System.Drawing.Point(101, 73);
            this.clbKorek.Name = "clbKorek";
            this.clbKorek.Size = new System.Drawing.Size(66, 154);
            this.clbKorek.TabIndex = 5;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(173, 12);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(23, 13);
            this.label4.TabIndex = 4;
            this.label4.Text = "bits";
            // 
            // NUDFudge
            // 
            this.NUDFudge.Location = new System.Drawing.Point(101, 41);
            this.NUDFudge.Maximum = new decimal(new int[] {
            32,
            0,
            0,
            0});
            this.NUDFudge.Minimum = new decimal(new int[] {
            2,
            0,
            0,
            0});
            this.NUDFudge.Name = "NUDFudge";
            this.NUDFudge.Size = new System.Drawing.Size(66, 20);
            this.NUDFudge.TabIndex = 3;
            this.NUDFudge.Value = new decimal(new int[] {
            2,
            0,
            0,
            0});
            // 
            // cbKeySize
            // 
            this.cbKeySize.FormattingEnabled = true;
            this.cbKeySize.Items.AddRange(new object[] {
            "64",
            "128",
            "152",
            "256",
            "512"});
            this.cbKeySize.Location = new System.Drawing.Point(101, 9);
            this.cbKeySize.Name = "cbKeySize";
            this.cbKeySize.Size = new System.Drawing.Size(66, 21);
            this.cbKeySize.TabIndex = 2;
            this.cbKeySize.Text = "128";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Location = new System.Drawing.Point(13, 45);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(67, 13);
            this.label3.TabIndex = 1;
            this.label3.Text = "Fudge factor";
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(13, 12);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(46, 13);
            this.label2.TabIndex = 0;
            this.label2.Text = "Key size";
            // 
            // tabWpa
            // 
            this.tabWpa.Controls.Add(this.label6);
            this.tabWpa.Controls.Add(this.btOpenDico);
            this.tabWpa.Controls.Add(this.tbWPADico);
            this.tabWpa.Location = new System.Drawing.Point(4, 22);
            this.tabWpa.Name = "tabWpa";
            this.tabWpa.Padding = new System.Windows.Forms.Padding(3);
            this.tabWpa.Size = new System.Drawing.Size(574, 243);
            this.tabWpa.TabIndex = 1;
            this.tabWpa.Text = "WPA";
            this.tabWpa.UseVisualStyleBackColor = true;
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(6, 9);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(45, 13);
            this.label6.TabIndex = 12;
            this.label6.Text = "Wordlist";
            // 
            // btOpenDico
            // 
            this.btOpenDico.Location = new System.Drawing.Point(493, 6);
            this.btOpenDico.Name = "btOpenDico";
            this.btOpenDico.Size = new System.Drawing.Size(75, 23);
            this.btOpenDico.TabIndex = 12;
            this.btOpenDico.Text = "Choose...";
            this.btOpenDico.UseVisualStyleBackColor = true;
            this.btOpenDico.Click += new System.EventHandler(this.btOpenDico_Click);
            // 
            // tbWPADico
            // 
            this.tbWPADico.AllowDrop = true;
            this.tbWPADico.Location = new System.Drawing.Point(111, 6);
            this.tbWPADico.Name = "tbWPADico";
            this.tbWPADico.Size = new System.Drawing.Size(372, 20);
            this.tbWPADico.TabIndex = 1;
            // 
            // cbForceAttack
            // 
            this.cbForceAttack.AutoSize = true;
            this.cbForceAttack.Location = new System.Drawing.Point(3, 52);
            this.cbForceAttack.Name = "cbForceAttack";
            this.cbForceAttack.Size = new System.Drawing.Size(115, 17);
            this.cbForceAttack.TabIndex = 9;
            this.cbForceAttack.Text = "Force attack mode";
            this.cbForceAttack.UseVisualStyleBackColor = true;
            // 
            // cbBssid
            // 
            this.cbBssid.AutoSize = true;
            this.cbBssid.Location = new System.Drawing.Point(3, 26);
            this.cbBssid.Name = "cbBssid";
            this.cbBssid.Size = new System.Drawing.Size(96, 17);
            this.cbBssid.TabIndex = 6;
            this.cbBssid.Text = "Specify BSSID";
            this.cbBssid.UseVisualStyleBackColor = true;
            this.cbBssid.CheckedChanged += new System.EventHandler(this.ShowHideEssidBssid);
            // 
            // tbBssid
            // 
            this.tbBssid.Location = new System.Drawing.Point(118, 24);
            this.tbBssid.MaxLength = 17;
            this.tbBssid.Name = "tbBssid";
            this.tbBssid.Size = new System.Drawing.Size(125, 20);
            this.tbBssid.TabIndex = 8;
            // 
            // tbEssid
            // 
            this.tbEssid.Location = new System.Drawing.Point(118, 3);
            this.tbEssid.MaxLength = 32;
            this.tbEssid.Name = "tbEssid";
            this.tbEssid.Size = new System.Drawing.Size(200, 20);
            this.tbEssid.TabIndex = 7;
            // 
            // btOpenCapFiles
            // 
            this.btOpenCapFiles.Location = new System.Drawing.Point(506, 4);
            this.btOpenCapFiles.Name = "btOpenCapFiles";
            this.btOpenCapFiles.Size = new System.Drawing.Size(75, 23);
            this.btOpenCapFiles.TabIndex = 3;
            this.btOpenCapFiles.Text = "Choose...";
            this.btOpenCapFiles.UseVisualStyleBackColor = true;
            this.btOpenCapFiles.Click += new System.EventHandler(this.btOpenCapFiles_Click);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(6, 9);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(60, 13);
            this.label1.TabIndex = 2;
            this.label1.Text = "Filename(s)";
            // 
            // btLaunchCrack
            // 
            this.btLaunchCrack.Location = new System.Drawing.Point(506, 410);
            this.btLaunchCrack.Name = "btLaunchCrack";
            this.btLaunchCrack.Size = new System.Drawing.Size(75, 23);
            this.btLaunchCrack.TabIndex = 1;
            this.btLaunchCrack.Text = "Launch";
            this.btLaunchCrack.UseVisualStyleBackColor = true;
            this.btLaunchCrack.Click += new System.EventHandler(this.btLaunchCrack_Click);
            // 
            // tbFilenames
            // 
            this.tbFilenames.AllowDrop = true;
            this.tbFilenames.Location = new System.Drawing.Point(72, 6);
            this.tbFilenames.Name = "tbFilenames";
            this.tbFilenames.Size = new System.Drawing.Size(424, 20);
            this.tbFilenames.TabIndex = 0;
            // 
            // tabPage2
            // 
            this.tabPage2.Controls.Add(this.btLaunchAirodump);
            this.tabPage2.Location = new System.Drawing.Point(4, 22);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Padding = new System.Windows.Forms.Padding(3);
            this.tabPage2.Size = new System.Drawing.Size(597, 436);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "Airodump-ng";
            this.tabPage2.UseVisualStyleBackColor = true;
            // 
            // btLaunchAirodump
            // 
            this.btLaunchAirodump.Location = new System.Drawing.Point(244, 169);
            this.btLaunchAirodump.Name = "btLaunchAirodump";
            this.btLaunchAirodump.Size = new System.Drawing.Size(120, 60);
            this.btLaunchAirodump.TabIndex = 0;
            this.btLaunchAirodump.Text = "Launch";
            this.btLaunchAirodump.UseVisualStyleBackColor = true;
            this.btLaunchAirodump.Click += new System.EventHandler(this.btLaunchAirodump_Click);
            // 
            // tabPage3
            // 
            this.tabPage3.Controls.Add(this.lEncryptionText);
            this.tabPage3.Controls.Add(this.tbKeyPassphrase);
            this.tabPage3.Controls.Add(this.tbPMKDecap);
            this.tabPage3.Controls.Add(this.label10);
            this.tabPage3.Controls.Add(this.cbPMKDecap);
            this.tabPage3.Controls.Add(this.rbWPADecap);
            this.tabPage3.Controls.Add(this.rbWepDecap);
            this.tabPage3.Controls.Add(this.cbBssidDecap);
            this.tabPage3.Controls.Add(this.cbEssidDecap);
            this.tabPage3.Controls.Add(this.tbEssidDecap);
            this.tabPage3.Controls.Add(this.btLaunchAirdecap);
            this.tabPage3.Controls.Add(this.tbBssidDecap);
            this.tabPage3.Controls.Add(this.cbNotRemove80211);
            this.tabPage3.Controls.Add(this.btLoadDecapFile);
            this.tabPage3.Controls.Add(this.tbDecapFile);
            this.tabPage3.Controls.Add(this.label7);
            this.tabPage3.Location = new System.Drawing.Point(4, 22);
            this.tabPage3.Name = "tabPage3";
            this.tabPage3.Size = new System.Drawing.Size(597, 436);
            this.tabPage3.TabIndex = 2;
            this.tabPage3.Text = "Airdecap-ng";
            this.tabPage3.UseVisualStyleBackColor = true;
            // 
            // lEncryptionText
            // 
            this.lEncryptionText.AutoSize = true;
            this.lEncryptionText.Location = new System.Drawing.Point(10, 199);
            this.lEncryptionText.Name = "lEncryptionText";
            this.lEncryptionText.Size = new System.Drawing.Size(25, 13);
            this.lEncryptionText.TabIndex = 0;
            this.lEncryptionText.Text = "Key";
            // 
            // tbKeyPassphrase
            // 
            this.tbKeyPassphrase.Location = new System.Drawing.Point(126, 196);
            this.tbKeyPassphrase.Name = "tbKeyPassphrase";
            this.tbKeyPassphrase.Size = new System.Drawing.Size(200, 20);
            this.tbKeyPassphrase.TabIndex = 1;
            // 
            // tbPMKDecap
            // 
            this.tbPMKDecap.Location = new System.Drawing.Point(126, 238);
            this.tbPMKDecap.Name = "tbPMKDecap";
            this.tbPMKDecap.Size = new System.Drawing.Size(291, 20);
            this.tbPMKDecap.TabIndex = 1;
            // 
            // label10
            // 
            this.label10.AutoSize = true;
            this.label10.Location = new System.Drawing.Point(6, 141);
            this.label10.Name = "label10";
            this.label10.Size = new System.Drawing.Size(57, 13);
            this.label10.TabIndex = 14;
            this.label10.Text = "Encryption";
            // 
            // cbPMKDecap
            // 
            this.cbPMKDecap.AutoSize = true;
            this.cbPMKDecap.Location = new System.Drawing.Point(13, 228);
            this.cbPMKDecap.Name = "cbPMKDecap";
            this.cbPMKDecap.Size = new System.Drawing.Size(105, 30);
            this.cbPMKDecap.TabIndex = 0;
            this.cbPMKDecap.Text = "WPA Pairwise\r\nMaster Key (hex)";
            this.cbPMKDecap.UseVisualStyleBackColor = true;
            this.cbPMKDecap.CheckedChanged += new System.EventHandler(this.cbPMKDecap_CheckedChanged);
            // 
            // rbWPADecap
            // 
            this.rbWPADecap.AutoSize = true;
            this.rbWPADecap.Location = new System.Drawing.Point(126, 164);
            this.rbWPADecap.Name = "rbWPADecap";
            this.rbWPADecap.Size = new System.Drawing.Size(50, 17);
            this.rbWPADecap.TabIndex = 13;
            this.rbWPADecap.Text = "WPA";
            this.rbWPADecap.UseVisualStyleBackColor = true;
            this.rbWPADecap.CheckedChanged += new System.EventHandler(this.rbWPADecap_CheckedChanged);
            // 
            // rbWepDecap
            // 
            this.rbWepDecap.AutoSize = true;
            this.rbWepDecap.Checked = true;
            this.rbWepDecap.Location = new System.Drawing.Point(126, 141);
            this.rbWepDecap.Name = "rbWepDecap";
            this.rbWepDecap.Size = new System.Drawing.Size(50, 17);
            this.rbWepDecap.TabIndex = 12;
            this.rbWepDecap.TabStop = true;
            this.rbWepDecap.Text = "WEP";
            this.rbWepDecap.UseVisualStyleBackColor = true;
            this.rbWepDecap.CheckedChanged += new System.EventHandler(this.rbWepDecap_CheckedChanged);
            // 
            // cbBssidDecap
            // 
            this.cbBssidDecap.AutoSize = true;
            this.cbBssidDecap.Location = new System.Drawing.Point(9, 101);
            this.cbBssidDecap.Name = "cbBssidDecap";
            this.cbBssidDecap.Size = new System.Drawing.Size(96, 17);
            this.cbBssidDecap.TabIndex = 11;
            this.cbBssidDecap.Text = "Specify BSSID";
            this.cbBssidDecap.UseVisualStyleBackColor = true;
            this.cbBssidDecap.CheckedChanged += new System.EventHandler(this.ShowHideEssidBssidDecap);
            // 
            // cbEssidDecap
            // 
            this.cbEssidDecap.AutoSize = true;
            this.cbEssidDecap.Location = new System.Drawing.Point(9, 76);
            this.cbEssidDecap.Name = "cbEssidDecap";
            this.cbEssidDecap.Size = new System.Drawing.Size(96, 17);
            this.cbEssidDecap.TabIndex = 10;
            this.cbEssidDecap.Text = "Specify ESSID";
            this.cbEssidDecap.UseVisualStyleBackColor = true;
            this.cbEssidDecap.CheckedChanged += new System.EventHandler(this.ShowHideEssidBssidDecap);
            // 
            // tbEssidDecap
            // 
            this.tbEssidDecap.Location = new System.Drawing.Point(126, 74);
            this.tbEssidDecap.MaxLength = 32;
            this.tbEssidDecap.Name = "tbEssidDecap";
            this.tbEssidDecap.Size = new System.Drawing.Size(200, 20);
            this.tbEssidDecap.TabIndex = 9;
            // 
            // btLaunchAirdecap
            // 
            this.btLaunchAirdecap.Location = new System.Drawing.Point(506, 410);
            this.btLaunchAirdecap.Name = "btLaunchAirdecap";
            this.btLaunchAirdecap.Size = new System.Drawing.Size(75, 23);
            this.btLaunchAirdecap.TabIndex = 7;
            this.btLaunchAirdecap.Text = "Launch";
            this.btLaunchAirdecap.UseVisualStyleBackColor = true;
            this.btLaunchAirdecap.Click += new System.EventHandler(this.btLaunchAirdecap_Click);
            // 
            // tbBssidDecap
            // 
            this.tbBssidDecap.Location = new System.Drawing.Point(126, 99);
            this.tbBssidDecap.MaxLength = 17;
            this.tbBssidDecap.Name = "tbBssidDecap";
            this.tbBssidDecap.Size = new System.Drawing.Size(125, 20);
            this.tbBssidDecap.TabIndex = 5;
            // 
            // cbNotRemove80211
            // 
            this.cbNotRemove80211.AutoSize = true;
            this.cbNotRemove80211.Location = new System.Drawing.Point(9, 45);
            this.cbNotRemove80211.Name = "cbNotRemove80211";
            this.cbNotRemove80211.Size = new System.Drawing.Size(161, 17);
            this.cbNotRemove80211.TabIndex = 3;
            this.cbNotRemove80211.Text = "Don\'t remove 802.11 header";
            this.cbNotRemove80211.UseVisualStyleBackColor = true;
            // 
            // btLoadDecapFile
            // 
            this.btLoadDecapFile.Location = new System.Drawing.Point(506, 4);
            this.btLoadDecapFile.Name = "btLoadDecapFile";
            this.btLoadDecapFile.Size = new System.Drawing.Size(75, 23);
            this.btLoadDecapFile.TabIndex = 2;
            this.btLoadDecapFile.Text = "Choose...";
            this.btLoadDecapFile.UseVisualStyleBackColor = true;
            this.btLoadDecapFile.Click += new System.EventHandler(this.btLoadDecapFile_Click);
            // 
            // tbDecapFile
            // 
            this.tbDecapFile.Location = new System.Drawing.Point(72, 6);
            this.tbDecapFile.Name = "tbDecapFile";
            this.tbDecapFile.Size = new System.Drawing.Size(424, 20);
            this.tbDecapFile.TabIndex = 1;
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(6, 9);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(49, 13);
            this.label7.TabIndex = 0;
            this.label7.Text = "Filename";
            // 
            // tabPage4
            // 
            this.tabPage4.Controls.Add(this.btLaunchWzcook);
            this.tabPage4.Location = new System.Drawing.Point(4, 22);
            this.tabPage4.Name = "tabPage4";
            this.tabPage4.Size = new System.Drawing.Size(597, 436);
            this.tabPage4.TabIndex = 3;
            this.tabPage4.Text = "WZCook";
            this.tabPage4.UseVisualStyleBackColor = true;
            // 
            // btLaunchWzcook
            // 
            this.btLaunchWzcook.Location = new System.Drawing.Point(244, 169);
            this.btLaunchWzcook.Name = "btLaunchWzcook";
            this.btLaunchWzcook.Size = new System.Drawing.Size(120, 60);
            this.btLaunchWzcook.TabIndex = 0;
            this.btLaunchWzcook.Text = "Launch";
            this.btLaunchWzcook.UseVisualStyleBackColor = true;
            this.btLaunchWzcook.Click += new System.EventHandler(this.btLaunchWzcook_Click);
            // 
            // Faircrack
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(610, 470);
            this.Controls.Add(this.tabControl1);
            this.MaximizeBox = false;
            this.MaximumSize = new System.Drawing.Size(618, 497);
            this.MinimumSize = new System.Drawing.Size(618, 497);
            this.Name = "Faircrack";
            this.Text = "Aircrack-ng GUI";
            this.tabControl1.ResumeLayout(false);
            this.tabPage1.ResumeLayout(false);
            this.tabPage1.PerformLayout();
            this.pAdvancedOptions.ResumeLayout(false);
            this.pAdvancedOptions.PerformLayout();
            this.tabWepWpa.ResumeLayout(false);
            this.tabWep.ResumeLayout(false);
            this.tabWep.PerformLayout();
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.NUDkbBrute)).EndInit();
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.NUDFudge)).EndInit();
            this.tabWpa.ResumeLayout(false);
            this.tabWpa.PerformLayout();
            this.tabPage2.ResumeLayout(false);
            this.tabPage3.ResumeLayout(false);
            this.tabPage3.PerformLayout();
            this.tabPage4.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TabControl tabControl1;
        private System.Windows.Forms.TabPage tabPage1;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Button btLaunchCrack;
        private System.Windows.Forms.TextBox tbFilenames;
        private System.Windows.Forms.TabPage tabPage2;
        private System.Windows.Forms.TabPage tabPage3;
        private System.Windows.Forms.TabPage tabPage4;
        private System.Windows.Forms.Button btOpenCapFiles;
        private System.Windows.Forms.TabControl tabWepWpa;
        private System.Windows.Forms.TabPage tabWep;
        private System.Windows.Forms.TabPage tabWpa;
        private System.Windows.Forms.TextBox tbEssid;
        private System.Windows.Forms.CheckBox cbBssid;
        private System.Windows.Forms.CheckBox cbEssid;
        private System.Windows.Forms.TextBox tbBssid;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.CheckBox cbForceAttack;
        private System.Windows.Forms.ComboBox cbKeySize;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.NumericUpDown NUDFudge;
        private System.Windows.Forms.CheckedListBox clbKorek;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.CheckBox cbBCD;
        private System.Windows.Forms.CheckBox cbAlphanum;
        private System.Windows.Forms.Button btLaunchWzcook;
        private System.Windows.Forms.CheckBox cbFritzbox;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.CheckBox cbSingleBrute;
        private System.Windows.Forms.CheckBox cbMultiThreading;
        private System.Windows.Forms.Label lkbBrute;
        private System.Windows.Forms.NumericUpDown NUDkbBrute;
        private System.Windows.Forms.Panel pAdvancedOptions;
        private System.Windows.Forms.CheckBox cbAdvancedOptions;
        private System.Windows.Forms.Button btLaunchAirodump;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Button btOpenDico;
        private System.Windows.Forms.TextBox tbWPADico;
        private System.Windows.Forms.Button btLoadDecapFile;
        private System.Windows.Forms.TextBox tbDecapFile;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.CheckBox cbNotRemove80211;
        private System.Windows.Forms.TextBox tbBssidDecap;
        private System.Windows.Forms.Button btLaunchAirdecap;
        private System.Windows.Forms.TextBox tbEssidDecap;
        private System.Windows.Forms.CheckBox cbPMKDecap;
        private System.Windows.Forms.CheckBox cbBssidDecap;
        private System.Windows.Forms.CheckBox cbEssidDecap;
        private System.Windows.Forms.TextBox tbPMKDecap;
        private System.Windows.Forms.TextBox tbKeyPassphrase;
        private System.Windows.Forms.Label lEncryptionText;
        private System.Windows.Forms.RadioButton rbWepDecap;
        private System.Windows.Forms.Label label10;
        private System.Windows.Forms.RadioButton rbWPADecap;
    }
}

