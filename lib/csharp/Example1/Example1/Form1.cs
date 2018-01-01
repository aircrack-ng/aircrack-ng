// License: BSD
// Copyright (C) 2011-2018 Thomas d'Otreppe
using System;
using System.Windows.Forms;
using WirelessPanda.Readers;

namespace Example1
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        /// <summary>
        /// Load file
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void button1_Click(object sender, EventArgs e)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.Multiselect = false;
            if (ofd.ShowDialog() == System.Windows.Forms.DialogResult.OK)
            {
                // Load file
                Reader reader = new UniversalReader(ofd.FileName);


                try
                {
                    // and parse it
                    reader.Read();

                    // Add Datatables
                    this.dataGridView1.DataSource = reader.Dataset.Tables[Reader.ACCESSPOINTS_DATATABLE];
                    this.dataGridView2.DataSource = reader.Dataset.Tables[Reader.STATIONS_DATATABLE];
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Exception: " + ex.Message, this.Text, MessageBoxButtons.OK, MessageBoxIcon.Error);
                }

                // Set file type
                this.lblFiletype.Text = reader.ReaderType;

                // Set filename
                this.lblFilename.Text = reader.Filename;

                // Indicate if parsing was successful
                if (reader.ParseSuccess)
                {
                    this.lblParsed.Text = "Yes";
                }
                else
                {
                    this.lblParsed.Text = "No";
                }
            }
        }

        private void Form1_SizeChanged(object sender, EventArgs e)
        {
            Form f = sender as Form;
            this.label1.Left = (f.Width - this.label1.Width) / 2;
            this.label2.Left = (f.Width - this.label2.Width) / 2;
        }
    }
}
