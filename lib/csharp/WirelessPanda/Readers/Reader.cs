// License: BSD/LGPL
// Copyright (C) 2011 Thomas d'Otreppe
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data;
using System.IO;

namespace WirelessPanda.Readers
{
    public class Reader
    {
        public const string ACCESSPOINTS_DATATABLE = "Access Points";
        public const string STATIONS_DATATABLE = "Stations";


        #region Private members
        private DataSet _dataset = new DataSet();
        private List<AccessPoint> _accessPoints = new List<AccessPoint>();
        private List<Station> _stations = new List<Station>();
        private string _filename = string.Empty;
        private bool _parseSuccess = false;
        #endregion

        #region Properties

        /// <summary>
        /// Returns true if the file exist
        /// </summary>
        public bool FileExist
        {
            get
            {
                return File.Exists(this._filename);
            }
        }

        /// <summary>
        /// DataSet containing 2 tables: "Access Points" and "Stations"
        /// </summary>
        public virtual DataSet Dataset
        {
            get
            {
                return this._dataset;
            }
        }

        /// <summary>
        /// Was the file parsed successfully?
        /// </summary>
        public bool ParseSuccess
        {
            get
            {
                return this._parseSuccess;
            }
            protected set
            {
                this._parseSuccess = value;
            }
        }
        /// <summary>
        /// Array of access points
        /// </summary>
        public virtual AccessPoint[] AccessPoints
        {
            get
            {
                return this._accessPoints.ToArray().Clone() as AccessPoint[];
            }
        }
        

        /// <summary>
        /// Array of stations
        /// </summary>
        public virtual Station[] Stations
        {
            get
            {
                return this._stations.ToArray().Clone() as Station[];
            }
        }

        /// <summary>
        /// Filename
        /// </summary>
        public string Filename
        {
            get
            {
                return this._filename;
            }
        }

        /// <summary>
        /// Reader type
        /// </summary>
        public virtual string ReaderType
        {
            get
            {
                return "Unknown";
            }
        }

        /// <summary>
        /// Reader type
        /// </summary>
        protected virtual string DATE_FORMAT
        {
            get
            {
                return null;
            }
        }

        /// <summary>
        /// Reader type
        /// </summary>
        protected virtual string ALT_DATE_FORMAT
        {
            get
            {
                return null;
            }
        }
        #endregion

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="filename">Filename (doesn't need to exist now but MUST when using Read() )</param>
        public Reader(string filename)
        {
            if (string.IsNullOrEmpty(filename))
            {
                throw new FileNotFoundException("Filename cannot be null or empty");
            }

            this._filename = filename;
        }

        protected void Clear()
        {
            // Clear all the values and re-create datatables
            this._dataset.Tables.Clear();
            this._accessPoints.Clear();
            this._stations.Clear();

            this._parseSuccess = false;
        }

        /// <summary>
        /// Open the file and returns its content
        /// </summary>
        /// <returns></returns>
        /// <exception cref="FileNotFoundException">File does not exist</exception>
        /// <exception cref="Exception">Fails to open file</exception>
        protected string[] getStrippedFileContent()
        {
            if (string.IsNullOrEmpty(this.Filename))
            {
                throw new FileNotFoundException("Filename cannot be null or empty");
            }

            FileInfo f = new FileInfo(this.Filename);
            if (!f.Exists)
            {
                throw new FileNotFoundException("File <" + this.Filename + "> does not exist");
            }

            // Returns an array with one empty string
            if (f.Length == 0)
            {
                return new string[] { string.Empty };
            }

            StreamReader sr = null;

            // Open the file
            try
            {
                sr = f.OpenText();
            }
            catch (Exception e)
            {
                throw new Exception("Failed to open <" + this.Filename + ">", e);
            }

            List<string> lines = new List<string>();

            // Read the file
            try
            {
                while (!sr.EndOfStream)
                {
                    lines.Add(sr.ReadLine().Trim());
                }
            }
            catch { /* Done or failure so stop */}

            // Close file
            try
            {
                sr.Close();
            }
            catch { }

            return lines.ToArray();
        }

        /// <summary>
        /// Read/Update the content of the file
        /// </summary>
        /// <returns>true if successful</returns>
        public virtual bool Read() { return this.ParseSuccess; }

        /// <summary>
        /// Generate the columns for the DataTable from the Hashtable (and in a specific order if needed)
        /// </summary>
        /// <param name="ht"></param>
        /// <returns></returns>
        private DataColumn[] getColumnsFromHashtable(Hashtable ht, Hashtable order)
        {
            List<DataColumn> columnList = new List<DataColumn>();

            if (ht != null)
            {
                if (order == null)
                {
                    // No specific order but that's not going to happen
                    foreach (string key in ht.Keys)
                    {
                        Type t = ht[key].GetType();
                        columnList.Add(new DataColumn(key, t));
                    }
                }
                else
                {
                    for (int i = 0; i < order.Count; i++)
                    {
                        Type t = ht[(string)order[i]].GetType();
                        columnList.Add(new DataColumn((string)order[i], t));
                    }
                }
            }

            return columnList.ToArray();
        }

        /// <summary>
        /// Add a station to the list
        /// </summary>
        /// <param name="s">Station</param>
        /// <returns></returns>
        protected bool addStation(Station s)
        {
            if (s == null)
            {
                return false;
            }

            // Create DataTable if needed
            if (!this._dataset.Tables.Contains(STATIONS_DATATABLE))
            {
                // Create Stations DataTable
                DataTable dtStations = new DataTable(STATIONS_DATATABLE);
                dtStations.CaseSensitive = true;
                
                // Create columns
                dtStations.Columns.AddRange(this.getColumnsFromHashtable(s.FieldsDictionary, s.FieldsOrder));
                
                // And add it to the dataset
                this._dataset.Tables.Add(dtStations);
            }

            // Add row
            DataRow dr = this._dataset.Tables[STATIONS_DATATABLE].NewRow();

            // Set value for each field
            foreach (string key in s.FieldsDictionary.Keys)
            {
                dr[key] = s.FieldsDictionary[key];
            }

            // Add row
            this._dataset.Tables[STATIONS_DATATABLE].Rows.Add(dr);

            // Add station to the list
            this._stations.Add(s);

            return true;
        }

        /// <summary>
        /// Link clients to their associated AP
        /// </summary>
        protected void LinkAPClients()
        {
            foreach (Station s in this._stations)
            {
                if (string.IsNullOrEmpty(s.BSSID))
                {
                    continue;
                }

                foreach (AccessPoint ap in this._accessPoints)
                {
                    if (ap.BSSID == s.BSSID)
                    {
                        ap.addClient(s);
                        break;
                    }
                }
            }

            //this._dataset.Tables[ACCESSPOINTS_DATATABLE].ChildRelations.Add(new DataRelation("Cients", this._dataset.Tables[ACCESSPOINTS_DATATABLE].Columns["BSSID"], this._dataset.Tables[STATIONS_DATATABLE].Columns["BSSID"]));
            //this._dataset.Tables[STATIONS_DATATABLE].ParentRelations.Add(new DataRelation("Associated AP", this._dataset.Tables[ACCESSPOINTS_DATATABLE].Columns["BSSID"], this._dataset.Tables[STATIONS_DATATABLE].Columns["BSSID"]));

        }

        /// <summary>
        /// Add Access Point to the list
        /// </summary>
        /// <param name="ap">Access Point</param>
        /// <returns></returns>
        protected bool addAccessPoint(AccessPoint ap)
        {
            if (ap == null)
            {
                return false;
            }

            // Create DataTable if needed
            if (!this._dataset.Tables.Contains(ACCESSPOINTS_DATATABLE))
            {
                // Create Access Points DataTable
                DataTable dtAPs = new DataTable(ACCESSPOINTS_DATATABLE);
                dtAPs.CaseSensitive = true;
                
                // Create columns
                dtAPs.Columns.AddRange(this.getColumnsFromHashtable(ap.FieldsDictionary, ap.FieldsOrder));

                this._dataset.Tables.Add(dtAPs);
            }

            // Add row
            DataRow dr = this._dataset.Tables[ACCESSPOINTS_DATATABLE].NewRow();

            foreach (string key in ap.FieldsDictionary.Keys)
            {
                dr[key] = ap.FieldsDictionary[key];
            }

            // Add row
            this._dataset.Tables[ACCESSPOINTS_DATATABLE].Rows.Add(dr);

            // Add the Access Point to the list
            this._accessPoints.Add(ap);

            return true;
        }

        /// <summary>
        /// Return the type of the file (and obviously, also the "name" of the reader to use
        /// </summary>
        /// <param name="path">Path to the file</param>
        /// <returns>Null if type is unknown or a string with the type</returns>
        public static string getFileType(string path)
        {
            Reader r = new CsvReader(path);

            try
            {
                r.Read();
            }
            catch 
            {
                r = new KismetCsvReader(path);

                try
                {
                    r.Read();
                }
                catch 
                {
                    r = new NetXMLReader(path);

                    try
                    {
                        r.Read();
                    }
                    catch { }
                }
            }

            if (!r.ParseSuccess)
            {
                return null;
            }

            return r.ReaderType;
        }

        /// <summary>
        /// Parse a string containing the date and time
        /// </summary>
        /// <param name="s">Date string</param>
        /// <returns>DateTime value</returns>
        /// <exception cref="ArgumentNullException">Date/Time string cannot be null or empty</exception>
        /// <exception cref="FormatException">Date Format is not set</exception>
        protected DateTime parseDateTime(string s)
        {
            if (string.IsNullOrEmpty(this.DATE_FORMAT))
            {
                throw new FormatException("Date Format is not set");
            }

            if (string.IsNullOrEmpty(s))
            {
                throw new ArgumentNullException("Date/Time string cannot be null or empty");
            }

            // Parse it
            DateTime ret = new DateTime();

            try
            {
                ret = DateTime.ParseExact(s.Trim(), DATE_FORMAT, null);
            }
            catch 
            {
                ret = DateTime.ParseExact(s.Trim(), ALT_DATE_FORMAT, null);
            }

            return ret;
        }
    }
}
