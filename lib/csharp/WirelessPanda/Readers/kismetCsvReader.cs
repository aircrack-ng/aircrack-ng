// License: BSD/LGPL
// Copyright (C) 2011-2018 Thomas d'Otreppe
using System;

namespace WirelessPanda.Readers
{
    public class KismetCsvReader : Reader
    {
        /// <summary>
        /// Date format (Same format for Kismet CSV and NetXML)
        /// </summary>
        protected override string DATE_FORMAT
        {
            get
            {
                return "ddd MMM dd HH:mm:ss yyyy";
            }
        }

        /// <summary>
        /// Date format (Same format for Kismet CSV and NetXML)
        /// </summary>
        protected override string ALT_DATE_FORMAT
        {
            get
            {
                return "ddd MMM  d HH:mm:ss yyyy";
            }
        }


        /// <summary>
        /// Reader type
        /// </summary>
        public override string ReaderType
        {
            get
            {
                return "Kismet CSV";
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="filename">Filename (doesn't need to exist now but MUST when using Read() )</param>
        public KismetCsvReader(string filename) : base(filename) { }

        /// <summary>
        /// Read/Update the content of the file
        /// </summary>
        /// <returns>true if successful</returns>
        /// <exception cref="FormatException">Airodump-ng CSV format unknown</exception>
        public override bool Read()
        {
            // Reset parsing status
            this.ParseSuccess = false;

            // Get the content of the file
            string[] content = this.getStrippedFileContent();

            // Check if this is really a kismet CSV file
            if (content.Length == 0)
            {
                throw new FormatException("Empty file");
            }

            this.ParseSuccess = (content[0] == "Network;NetType;ESSID;BSSID;Info;Channel;Cloaked;Encryption;Decrypted;MaxRate;MaxSeenRate;Beacon;LLC;Data;Crypt;Weak;Total;Carrier;Encoding;FirstTime;LastTime;BestQuality;BestSignal;BestNoise;GPSMinLat;GPSMinLon;GPSMinAlt;GPSMinSpd;GPSMaxLat;GPSMaxLon;GPSMaxAlt;GPSMaxSpd;GPSBestLat;GPSBestLon;GPSBestAlt;DataSize;IPType;IP;");
            if (!this.ParseSuccess)
            {
                throw new FormatException("Not a Kismet CSV file");
            }

            // Parse content
            for (int i = 1; i < content.Length && !string.IsNullOrEmpty(content[i]); i++)
            {
                string [] splitted = content[i].Split(';');

                // Check if there are enough elements
                if (splitted.Length < 39)
                {
                    continue;
                }

                AccessPoint ap = new AccessPoint();
                
                // Skip first element which is the network number (if someone cares about it, email me)
                ap.NetworkType = splitted[1].Trim();
                ap.ESSID = splitted[2].Trim();
                ap.ESSIDLength = (byte)splitted[2].Length;
                ap.BSSID = splitted[3].Trim();
                ap.Info = splitted[4].Trim();
                ap.Channel = int.Parse(splitted[5]);
                ap.Cloaked = (splitted[6].Trim().ToLower() == "yes");
                ap.Encryption = splitted[7].Trim();
                ap.Decrypted = (splitted[8].Trim().ToLower() == "yes");
                ap.MaxRate = double.Parse(splitted[9]);
                ap.MaxSeenRate = double.Parse(splitted[10]);
                ap.Beacon = ulong.Parse(splitted[11]);
                ap.LLC = ulong.Parse(splitted[12]);
                ap.DataFrames = ulong.Parse(splitted[13]);
                ap.Crypt = ulong.Parse(splitted[14]);
                ap.Weak = ulong.Parse(splitted[15]);
                ap.Total = ulong.Parse(splitted[16]);
                ap.Carrier = splitted[17].Trim();
                ap.Encoding = splitted[18].Trim();
                ap.FirstTimeSeen = this.parseDateTime(splitted[19]);
                ap.LastTimeSeen = this.parseDateTime(splitted[20]);
                ap.BestQuality = int.Parse(splitted[21]);
                ap.BestSignal = int.Parse(splitted[22]);
                ap.BestNoise = int.Parse(splitted[23]);
                ap.MinLocation = new Coordinates(splitted[24], splitted[25], splitted[26], splitted[27]);
                ap.MaxLocation = new Coordinates(splitted[28], splitted[29], splitted[30], splitted[31]);
                ap.BestLocation = new Coordinates(splitted[32], splitted[33], splitted[34], "");
                ap.DataSize = ulong.Parse(splitted[35]);
                ap.IPType = int.Parse(splitted[36]);
                ap.IP = splitted[37].Replace(" ", "");

                this.addAccessPoint(ap);
            }

            // No need to link stations and access points together since there are only access points.

            return true;
        }

        
    }
}
