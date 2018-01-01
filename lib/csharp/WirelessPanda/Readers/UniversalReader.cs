// License: BSD/LGPL
// Copyright (C) 2011-2018 Thomas d'Otreppe
using System;
using System.Data;

namespace WirelessPanda.Readers
{
    public class UniversalReader : Reader
    {
        /// <summary>
        /// Reader
        /// </summary>
        private Reader _reader = null;

        /// <summary>
        /// File type
        /// </summary>
        /// <remarks>So that we have to check it only once</remarks>
        private string _fileType = string.Empty;

        #region Properties
        /// <summary>
        /// DataSet containing 2 tables: "Access Points" and "Stations"
        /// </summary>
        public override DataSet Dataset
        {
            get
            {
                return this._reader.Dataset;
            }
        }

        /// <summary>
        /// Array of access points
        /// </summary>
        public override AccessPoint[] AccessPoints
        {
            get
            {
                return this._reader.AccessPoints;
            }
        }

        /// <summary>
        /// Array of stations
        /// </summary>
        public override Station[] Stations
        {
            get
            {
                return this._reader.Stations;
            }
        }

        /// <summary>
        /// Reader type
        /// </summary>
        public override string ReaderType
        {
            get
            {
                return "Universal: Airodump-ng CSV, Kismet CSV, Kismet NetXML";
            }
        }
        #endregion

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="filename">Filename (doesn't need to exist now but MUST when using Read() )</param>
        public UniversalReader(string filename) : base(filename) { }

        /// <summary>
        /// Read/Update the content of the file
        /// </summary>
        /// <returns>true if successful</returns>
        public override bool Read()
        {
            this.ParseSuccess = false;

            if (string.IsNullOrEmpty(this._fileType))
            {
                this._fileType = Reader.getFileType(this.Filename);
            }

            switch (this._fileType)
            {
                case "Airodump-ng CSV":
                    this._reader = new CsvReader(this.Filename);
                    break;
                case "Kismet CSV":
                    this._reader = new KismetCsvReader(this.Filename);
                    break;
                case "Kismet NetXML":
                    this._reader = new NetXMLReader(this.Filename);
                    break;
                default:
                    throw new FormatException("Unknown file format, can't parse");
                    break;
            }

            this.ParseSuccess = this._reader.Read();

            return this.ParseSuccess;
        }
    }
}
