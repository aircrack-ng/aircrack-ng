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
                string [] split = content[i].Split(';');

                // Check if there are enough elements
                if (split.Length < 39)
                {
                    continue;
                }

                AccessPoint ap = new AccessPoint();
                
                // Skip first element which is the network number (if someone cares about it, email me)
                ap.NetworkType = split[1].Trim();
                ap.ESSID = split[2].Trim();
                ap.ESSIDLength = (byte)split[2].Length;
                ap.BSSID = split[3].Trim();
                ap.Info = split[4].Trim();
                ap.Channel = int.Parse(split[5]);
                ap.Cloaked = (split[6].Trim().ToLower() == "yes");
                ap.Encryption = split[7].Trim();
                ap.Decrypted = (split[8].Trim().ToLower() == "yes");
                ap.MaxRate = double.Parse(split[9]);
                ap.MaxSeenRate = double.Parse(split[10]);
                ap.Beacon = ulong.Parse(split[11]);
                ap.LLC = ulong.Parse(split[12]);
                ap.DataFrames = ulong.Parse(split[13]);
                ap.Crypt = ulong.Parse(split[14]);
                ap.Weak = ulong.Parse(split[15]);
                ap.Total = ulong.Parse(split[16]);
                ap.Carrier = split[17].Trim();
                ap.Encoding = split[18].Trim();
                ap.FirstTimeSeen = this.parseDateTime(split[19]);
                ap.LastTimeSeen = this.parseDateTime(split[20]);
                ap.BestQuality = int.Parse(split[21]);
                ap.BestSignal = int.Parse(split[22]);
                ap.BestNoise = int.Parse(split[23]);
                ap.MinLocation = new Coordinates(split[24], split[25], split[26], split[27]);
                ap.MaxLocation = new Coordinates(split[28], split[29], split[30], split[31]);
                ap.BestLocation = new Coordinates(split[32], split[33], split[34], "");
                ap.DataSize = ulong.Parse(split[35]);
                ap.IPType = int.Parse(split[36]);
                ap.IP = split[37].Replace(" ", "");

                this.addAccessPoint(ap);
            }

            // No need to link stations and access points together since there are only access points.

            return true;
        }

        
    }
}
